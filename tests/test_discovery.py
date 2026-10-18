# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic UDP tests; no HA installation, live device, or network required.

Only HA's Platform enum is stubbed. All framing, parsing, discovery, and endpoint
lifecycle calls under test use production code (the endpoint itself is mocked).
"""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import sys
import unittest
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, Mock, patch

PACKAGE = "_discovery_tests_352"
root = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = ModuleType(PACKAGE)
package.__path__ = [str(root)]
protocols = ModuleType(f"{PACKAGE}.protocols")
protocols.__path__ = [str(root / "protocols")]
ha_const = ModuleType("homeassistant.const")
ha_const.Platform = StrEnum("Platform", "FAN SENSOR LIGHT SELECT SWITCH")
with patch.dict(
    sys.modules,
    {
        PACKAGE: package,
        f"{PACKAGE}.protocols": protocols,
        "homeassistant": ModuleType("homeassistant"),
        "homeassistant.const": ha_const,
    },
):
    discovery = importlib.import_module(f"{PACKAGE}.discovery")
    base = importlib.import_module(f"{PACKAGE}.protocols.base")
    models = importlib.import_module(f"{PACKAGE}.models")

HOST = "192.0.2.123"
MAC = bytes.fromhex("123456789abc")
AUTH = 0xD3E7
PEER = (HOST, 11530)
LOGGER = discovery.__name__


def packet(payload=None, *, operation=6, sequence=42, mac=MAC, wire_type=2):
    if payload is None:
        payload = b"\x23" + ipaddress.IPv4Address(HOST).packed + mac
    return base.build_outer_frame(
        models.CommandContext(
            identity=models.HeaderIdentity(
                mac=mac,
                company=0xF1,
                wire_type=wire_type,
                auth=AUTH,
            ),
            outer_sequence=sequence,
        ),
        payload,
        operation=operation,
    )


def protocol():
    return discovery._ReadOnlyDiscoveryProtocol(HOST, MAC, {2}, {42})


class DecodeTests(unittest.TestCase):
    def test_discovery_success_and_no_duplicate_count(self):
        receiver = protocol()
        receiver.datagram_received(packet(), PEER)
        self.assertEqual(receiver.result.mac, "12:34:56:78:9a:bc")
        self.assertEqual(receiver.result.auth, AUTH)
        self.assertEqual(receiver.accepted, "discovery_reply")
        self.assertTrue(receiver.response_received.is_set())
        receiver.datagram_received(b"bad", PEER)
        self.assertEqual(receiver.received, 1)

    def test_passive_type2_layouts_preserved(self):
        for payload in (
            b"\x02" + b"\x5a\xa1" + bytes(30),
            b"\x02" + (b"\x5a\xa1" + bytes(30)) * 2,
        ):
            with self.subTest(length=len(payload)):
                receiver = protocol()
                receiver.datagram_received(packet(payload, operation=4), PEER)
                self.assertEqual(receiver.accepted, "passive_state")
                self.assertIsNotNone(receiver.result)

    def test_discovery_rejection_categories(self):
        valid = packet()
        cases = [
            (b"short", PEER, "outer_too_short"),
            (b"\x00" + valid[1:], PEER, "outer_header"),
            (valid[:8] + b"\x06" + valid[9:], PEER, "outer_declared_length"),
            (valid + b"x", PEER, "outer_length_mismatch"),
            (valid, (HOST, 1234), "source_port_or_shape"),
            (packet(operation=5), PEER, "discovery_operation"),
            (packet(b"\x23"), PEER, "discovery_payload"),
            (packet(valid[16:21] + bytes(6)), PEER, "embedded_mac_mismatch"),
            (
                packet(b"\x23" + bytes([192, 0, 2, 124]) + MAC),
                PEER,
                "advertised_address_mismatch",
            ),
            (packet(mac=bytes.fromhex("abcdef123456")), PEER, "target_mac_mismatch"),
            (packet(sequence=43), PEER, "sequence_mismatch"),
        ]
        for data, peer, reason in cases:
            with self.subTest(reason=reason):
                receiver = protocol()
                receiver.datagram_received(data, peer)
                self.assertIsNone(receiver.result)
                self.assertEqual(receiver.discovery_rejections, {reason: 1})

    def test_passive_rejections(self):
        for data, reason in [
            (packet(b"\x02\x5a\xa1", operation=4), "state_payload_layout"),
            (packet(operation=4, wire_type=1), "state_wire_type"),
            (
                packet(operation=4, mac=bytes.fromhex("abcdef123456")),
                "target_mac_mismatch",
            ),
        ]:
            with self.subTest(reason=reason):
                receiver = protocol()
                receiver.datagram_received(data, PEER)
                self.assertEqual(receiver.state_rejections, {reason: 1})
                self.assertIsNone(receiver.result)

    def test_f072_crc_is_not_relaxed(self):
        frame = bytearray(40)
        frame[:2] = b"\xf0\x72"
        frame[6:8] = b"\x84\x02"
        frame[-2:] = base.crc16_genibus(frame[2:-2]).to_bytes(2, "big")
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                if corrupt:
                    frame[-1] ^= 1
                reasons = []
                result = discovery._decode_passive_status(
                    packet(b"\x01" + frame, operation=4, wire_type=3),
                    PEER,
                    HOST,
                    MAC,
                    {3},
                    on_reject=reasons.append,
                )
                self.assertEqual(result is None, corrupt)
                self.assertEqual(reasons, ["state_crc"] if corrupt else [])

    def test_shared_socket_noise_and_log_privacy(self):
        receiver = protocol()
        for _ in range(100):
            receiver.datagram_received(b"secret-raw-payload", ("192.0.2.124", 11530))
        receiver.datagram_received(packet(sequence=43), PEER)
        with self.assertLogs(LOGGER, level="DEBUG") as logs:
            receiver.log_summary("timeout")
        message = "\n".join(logs.output)
        for expected in (
            "received=101",
            "target_received=1",
            "other_received=100",
            "sequence_mismatch",
        ):
            self.assertIn(expected, message)
        for secret in (
            HOST,
            "192.0.2.124",
            MAC.hex(),
            "12:34:56:78:9a:bc",
            str(AUTH),
            "d3e7",
            "secret-raw-payload",
            packet().hex(),
        ):
            self.assertNotIn(secret, message)
        self.assertEqual(sum(receiver.discovery_rejections.values()), 1)


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def run_probe(self, *, reply=None, passive=0, bind_error=False):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()
        if bind_error:
            acquire.side_effect = OSError("sensitive bind details")
        elif reply:

            def deliver(data, _target):
                callback = acquire.call_args.args[0]
                self.assertEqual(data, discovery.encode_discovery_probe(MAC, 2, 42))
                if reply == "active":
                    callback(packet(), PEER)
                else:
                    asyncio.get_running_loop().call_later(
                        0.025,
                        callback,
                        packet(),
                        PEER,
                    )

            endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
        ):
            try:
                result = await discovery.async_discover_device(
                    HOST,
                    MAC,
                    (2,),
                    response_timeout=0.02,
                    passive_timeout=passive,
                )
            except discovery.DiscoveryError:
                result = None
        if bind_error:
            release.assert_not_awaited()
        else:
            release.assert_awaited_once_with(endpoint, acquire.call_args.args[0])
        message = "\n".join(logs.output)
        self.assertNotIn(HOST, message)
        self.assertNotIn("sensitive bind details", message)
        return result, message, endpoint

    async def test_no_packets_active_timeout(self):
        result, logs, endpoint = await self.run_probe()
        self.assertIsNone(result)
        self.assertIn("outcome=timeout phase=active", logs)
        self.assertIn("received=0", logs)
        self.assertEqual(endpoint.sendto.call_count, 2)

    async def test_no_packets_passive_timeout(self):
        result, logs, _ = await self.run_probe(passive=0.02)
        self.assertIsNone(result)
        self.assertIn("outcome=active_timeout", logs)
        self.assertIn("outcome=timeout phase=passive", logs)

    async def test_active_success(self):
        result, logs, endpoint = await self.run_probe(reply="active")
        self.assertIsNotNone(result)
        self.assertIn("outcome=success phase=active", logs)
        self.assertEqual(endpoint.sendto.call_count, 1)

    async def test_late_reply_success(self):
        result, logs, _ = await self.run_probe(reply="late", passive=0.1)
        self.assertIsNotNone(result)
        self.assertIn("outcome=success phase=passive", logs)

    async def test_bind_error(self):
        result, logs, _ = await self.run_probe(bind_error=True)
        self.assertIsNone(result)
        self.assertIn("outcome=endpoint_error phase=bind", logs)

    async def test_cancellation_releases_endpoint(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
        ):
            task = asyncio.create_task(discovery.async_discover_device(HOST, MAC, (2,)))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        release.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
