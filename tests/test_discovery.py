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
    m25 = importlib.import_module(f"{PACKAGE}.protocols.m25")

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
        frame = bytearray(39)
        frame[:2] = b"\xf0\x72"
        frame[5:7] = b"\x84\x02"
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

    def test_matching_mac_from_wrong_host_is_not_accepted(self):
        receiver = protocol()
        other_host = "192.0.2.124"
        data = packet(b"\x23" + ipaddress.IPv4Address(other_host).packed + MAC)
        receiver.datagram_received(data, (other_host, 11530))
        self.assertIsNone(receiver.result)
        self.assertEqual(receiver.target_received, 0)

    def test_wrong_discovery_family_is_not_accepted(self):
        receiver = protocol()
        receiver.datagram_received(packet(wire_type=3), PEER)
        self.assertIsNone(receiver.result)
        self.assertEqual(receiver.discovery_rejections, {"discovery_wire_type": 1})

    def test_passive_m25_uses_f5_response_marker(self):
        for marker, accepted in ((0xF5, True), (0xE5, False)):
            with self.subTest(marker=marker):
                result = discovery._decode_passive_status(
                    packet(
                        bytes((3, marker, 0xA1)) + bytes(14), operation=4, wire_type=1
                    ),
                    PEER,
                    HOST,
                    MAC,
                    {1},
                )
                self.assertEqual(result is not None, accepted)

    def test_m25_apk_incoming_route_in_discovery_and_runtime(self):
        data = packet(b"\x04\xf5\xa1" + bytes(14), operation=4, wire_type=1)
        self.assertIsNotNone(
            discovery._decode_passive_status(data, PEER, HOST, MAC, {1})
        )
        self.assertIsNotNone(m25.M25Codec().decode(data, PEER))


class NetworkDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def test_collects_and_deduplicates_replies_and_valid_passive_states(self):
        receiver = discovery._ReadOnlyNetworkDiscoveryProtocol({42})
        receiver.datagram_received(packet(), PEER)
        receiver.datagram_received(packet(), PEER)
        self.assertEqual(len(receiver.results), 1)
        self.assertEqual(receiver.results[MAC.hex(":")].auth, AUTH)
        receiver.datagram_received(
            packet(b"\x02\x5a\xa1" + bytes(30), sequence=999, operation=4), PEER
        )
        self.assertEqual(len(receiver.results), 1)
        self.assertEqual(receiver.received, 3)
        self.assertTrue(receiver.response_received.is_set())

    def test_drops_unrelated_invalid_and_unmatched_discovery_packets(self):
        receiver = discovery._ReadOnlyNetworkDiscoveryProtocol({42})
        for raw, source in (
            (b"bad", PEER),
            (packet(), (HOST, 1234)),
            (packet(sequence=43), PEER),
            (packet(mac=b"\xff" * 6), PEER),
            (packet(wire_type=5), PEER),
        ):
            receiver.datagram_received(raw, source)
        self.assertEqual(receiver.results, {})
        self.assertFalse(receiver.response_received.is_set())

    def test_configured_device_does_not_signal_an_eligible_result(self):
        receiver = discovery._ReadOnlyNetworkDiscoveryProtocol(
            {42}, frozenset({MAC.hex(":")})
        )
        receiver.datagram_received(packet(), PEER)
        receiver.datagram_received(
            packet(b"\x02\x5a\xa1" + bytes(30), operation=4), PEER
        )
        self.assertEqual(receiver.results, {})
        self.assertFalse(receiver.response_received.is_set())

    def test_passive_devices_of_every_protocol_family_can_be_collected(self):
        for wire in (1, 2, 3, 4):
            with self.subTest(wire=wire):
                if wire == 1:
                    payload = b"\x04\xf5\xa1" + bytes(14)
                elif wire == 2:
                    payload = b"\x02\x5a\xa1" + bytes(30)
                else:
                    frame = bytearray(39 if wire == 3 else 38)
                    frame[:2] = b"\xf0\x72"
                    frame[5:7] = b"\x84\x02"
                    frame[-2:] = base.crc16_genibus(frame[2:-2]).to_bytes(2, "big")
                    payload = b"\x01" + frame
                receiver = discovery._ReadOnlyNetworkDiscoveryProtocol({42})
                receiver.datagram_received(
                    packet(payload, operation=4, wire_type=wire), PEER
                )
                self.assertEqual(receiver.results[MAC.hex(":")].wire_type, wire)

    async def test_broadcast_scan_returns_early_read_only_and_logs_no_identity(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()

        def deliver(raw, target):
            self.assertEqual(target, ("255.255.255.255", 11530))
            self.assertEqual(raw[2:8], b"\xff" * 6)
            self.assertEqual(raw[16:], b"\x23")
            if raw[13] == 2 and raw[1] == 0x00:
                acquire.call_args.args[0](
                    packet(sequence=int.from_bytes(raw[10:12], "big")), PEER
                )

        endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
            self.assertLogs(LOGGER, level="DEBUG") as logs,
        ):
            result = await asyncio.wait_for(
                discovery.async_discover_devices(), timeout=1
            )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].auth, AUTH)
        self.assertLessEqual(endpoint.sendto.call_count, 8)
        self.assertEqual(
            {call.args[0][1] for call in endpoint.sendto.call_args_list}, {0x00, 0x04}
        )
        release.assert_awaited_once_with(endpoint, acquire.call_args.args[0])
        message = "\n".join(logs.output)
        self.assertIn("devices=1", message)
        for private in (HOST, MAC.hex(":"), str(AUTH), packet().hex()):
            self.assertNotIn(private, message)

    async def test_no_reply_and_send_failure_return_empty_and_release_endpoint(self):
        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                endpoint = Mock()
                if blocked:
                    endpoint.sendto.side_effect = OSError("private routing details")
                acquire = AsyncMock(return_value=endpoint)
                release = AsyncMock()
                with (
                    patch.object(discovery, "async_acquire_udp_endpoint", acquire),
                    patch.object(discovery, "async_release_udp_endpoint", release),
                    self.assertLogs(LOGGER, level="DEBUG") as logs,
                ):
                    result = await discovery.async_discover_devices(
                        response_timeout=0.02
                    )
                self.assertEqual(result, ())
                release.assert_awaited_once()
                self.assertNotIn("private routing details", "\n".join(logs.output))

    async def test_default_window_catches_a_broadcast_after_thirty_seconds(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()
        real_sleep = asyncio.sleep
        real_wait_for = asyncio.wait_for
        waits = []
        timeouts = []
        scheduled = False

        async def scaled_sleep(delay):
            waits.append(delay)
            # Simulate seconds as milliseconds while preserving the default
            # scan duration and retry interval passed by production code.
            await real_sleep(delay / 1000)

        def scaled_wait_for(awaitable, timeout):
            timeouts.append(timeout)
            return real_wait_for(awaitable, timeout / 1000)

        def deliver(_raw, _target):
            nonlocal scheduled
            if not scheduled:
                scheduled = True
                callback = acquire.call_args.args[0]
                asyncio.get_running_loop().call_later(
                    0.030,
                    callback,
                    packet(b"\x02\x5a\xa1" + bytes(30), operation=4),
                    PEER,
                )

        endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
            patch.object(discovery.asyncio, "sleep", scaled_sleep),
            patch.object(discovery.asyncio, "wait_for", scaled_wait_for),
        ):
            result = await discovery.async_discover_devices()
        self.assertEqual(timeouts, [45])
        self.assertGreaterEqual(waits.count(5), 3)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].mac, MAC.hex(":"))
        self.assertGreater(endpoint.sendto.call_count, 16)
        release.assert_awaited_once()

    async def test_configured_device_keeps_scan_running_until_a_new_one_replies(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()
        new_mac = bytes.fromhex("123456789abd")
        new_host = "192.0.2.124"

        def deliver(raw, _target):
            if raw[13] != 2:
                return
            callback = acquire.call_args.args[0]
            sequence = int.from_bytes(raw[10:12], "big")
            callback(packet(sequence=sequence), PEER)
            if endpoint.sendto.call_count > 8:
                payload = b"\x23" + ipaddress.IPv4Address(new_host).packed + new_mac
                callback(
                    packet(payload, mac=new_mac, sequence=sequence),
                    (new_host, 11530),
                )

        endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
        ):
            result = await discovery.async_discover_devices(
                response_timeout=0.08,
                retry_interval=0.01,
                excluded_macs=frozenset({MAC.hex(":")}),
            )
        self.assertEqual([item.mac for item in result], [new_mac.hex(":")])
        self.assertGreater(endpoint.sendto.call_count, 8)
        release.assert_awaited_once()

    async def test_only_configured_devices_do_not_end_the_scan_early(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()

        def deliver(raw, _target):
            if raw[13] == 2:
                acquire.call_args.args[0](
                    packet(sequence=int.from_bytes(raw[10:12], "big")), PEER
                )

        endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
        ):
            result = await discovery.async_discover_devices(
                response_timeout=0.025,
                retry_interval=0.01,
                excluded_macs=frozenset({MAC.hex(":")}),
            )
        self.assertEqual(result, ())
        self.assertGreater(endpoint.sendto.call_count, 8)
        release.assert_awaited_once()

    async def test_retries_continue_after_two_lost_probe_batches(self):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()

        def deliver(raw, _target):
            if endpoint.sendto.call_count > 16 and raw[13] == 2:
                acquire.call_args.args[0](
                    packet(sequence=int.from_bytes(raw[10:12], "big")), PEER
                )

        endpoint.sendto.side_effect = deliver
        with (
            patch.object(discovery, "async_acquire_udp_endpoint", acquire),
            patch.object(discovery, "async_release_udp_endpoint", release),
        ):
            result = await discovery.async_discover_devices(
                response_timeout=0.045, retry_interval=0.01
            )
        self.assertEqual(len(result), 1)
        self.assertGreater(endpoint.sendto.call_count, 16)
        release.assert_awaited_once()

    async def test_bind_failure_and_cancel_release_resources(self):
        with (
            patch.object(
                discovery, "async_acquire_udp_endpoint", AsyncMock(side_effect=OSError)
            ),
            self.assertRaises(discovery.DiscoveryError),
        ):
            await discovery.async_discover_devices(response_timeout=0.02)
        endpoint = Mock()
        with (
            patch.object(
                discovery,
                "async_acquire_udp_endpoint",
                AsyncMock(return_value=endpoint),
            ),
            patch.object(
                discovery, "async_release_udp_endpoint", AsyncMock()
            ) as release,
        ):
            task = asyncio.create_task(discovery.async_discover_devices())
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        release.assert_awaited_once()


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


class CompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def run_device(self, *, mode, auth=None, company=0xF1, block_broadcast=False):
        endpoint = Mock()
        acquire = AsyncMock(return_value=endpoint)
        release = AsyncMock()

        def deliver(data, target):
            if block_broadcast and target[0] == "255.255.255.255":
                raise OSError("sensitive network routing details")
            outer = base.parse_outer_frame(data)
            self.assertIsNotNone(outer)
            # A simulated Plus either answers broadcast discovery only, gates
            # discovery on its credential, or implements state queries only.
            if mode == "broadcast":
                respond = target[0] == "255.255.255.255" and outer.payload == b"\x23"
            elif mode == "import":
                respond = (
                    outer.identity.auth == AUTH and outer.identity.company == company
                )
            elif mode == "state":
                respond = outer.payload == b"\x01\xa5\xa0\x11\x11\x00\x00"
                respond &= outer.identity.auth == AUTH
            elif mode == "seed":
                respond = outer.identity.auth == 0x0403 and outer.payload == b"\x23"
            else:
                respond = False
            if not respond:
                return
            payload = None
            operation = 6
            if mode == "state":
                payload = b"\x02\x5a\xa1" + bytes(30)
                operation = 4
            # Reply identity is authoritative even if a seed elicited it.
            callback = acquire.call_args.args[0]
            callback(
                packet(payload, sequence=outer.sequence, operation=operation), PEER
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
                    passive_timeout=0,
                    auth=auth,
                    company=company,
                    compatibility_probes=True,
                )
            except discovery.DiscoveryTimeoutError:
                result = None
        release.assert_awaited_once()
        for call in endpoint.sendto.call_args_list:
            data, target = call.args
            self.assertIn(target[0], (HOST, "255.255.255.255"))
            self.assertEqual(target[1], 11530)
            self.assertIn(data[16:], (b"\x23", b"\x01\xa5\xa0\x11\x11\x00\x00"))
        return result, endpoint, "\n".join(logs.output)

    async def test_broadcast_only_device(self):
        result, endpoint, _ = await self.run_device(mode="broadcast")
        self.assertIsNotNone(result)
        self.assertTrue(
            any(
                call.args[1][0] == "255.255.255.255"
                for call in endpoint.sendto.call_args_list
            )
        )

    async def test_imported_auth_and_company_reach_device(self):
        result, endpoint, logs = await self.run_device(
            mode="import", auth=AUTH, company=0xF5
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.auth, AUTH)
        self.assertEqual(
            endpoint.sendto.call_args.args[0][12:16], bytes.fromhex("f502d3e7")
        )
        self.assertIn("imported_auth=True", logs)
        for secret in (HOST, MAC.hex(), "d3e7", str(AUTH)):
            self.assertNotIn(secret, logs)

    async def test_state_query_bypasses_missing_find_implementation(self):
        result, _, logs = await self.run_device(mode="state", auth=AUTH)
        self.assertIsNotNone(result)
        self.assertIn("accepted=passive_state", logs)

    async def test_blocked_broadcast_still_tries_directed_state_read(self):
        result, _, logs = await self.run_device(
            mode="state", auth=AUTH, block_broadcast=True
        )
        self.assertIsNotNone(result)
        self.assertIn("send_errors=2", logs)
        self.assertNotIn("sensitive network routing details", logs)

    async def test_seed_is_not_persisted_as_control_identity(self):
        result, _, _ = await self.run_device(mode="seed")
        self.assertIsNotNone(result)
        self.assertEqual(result.auth, AUTH)
        self.assertNotEqual(result.auth, 0x0403)

    async def test_silent_device_is_not_added_and_traffic_is_bounded(self):
        result, endpoint, logs = await self.run_device(mode="silent")
        self.assertIsNone(result)
        self.assertEqual(endpoint.sendto.call_count, 14)
        self.assertIn("target_received=0", logs)

    async def test_retries_are_bounded_even_for_a_silent_device(self):
        sleep = asyncio.sleep

        async def advance_retry(_delay):
            await sleep(0)

        with patch.object(discovery.asyncio, "sleep", advance_retry):
            result, endpoint, _ = await self.run_device(mode="silent")
        self.assertIsNone(result)
        self.assertLessEqual(endpoint.sendto.call_count, 38)
        self.assertGreater(endpoint.sendto.call_count, 14)

    async def test_invalid_header_never_opens_endpoint(self):
        with patch.object(
            discovery, "async_acquire_udp_endpoint", AsyncMock()
        ) as acquire:
            for kwargs in ({"auth": -1}, {"auth": 65536}, {"company": 256}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    await discovery.async_discover_device(HOST, MAC, (2,), **kwargs)
            acquire.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
