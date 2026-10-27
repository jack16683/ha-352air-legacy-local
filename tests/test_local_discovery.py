# SPDX-License-Identifier: GPL-3.0-or-later
"""CoAP interoperability, malformed packets, and local-only discovery lifecycle."""

from __future__ import annotations

import asyncio
import json
import random
import sys
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from test_discovery import AUTH, HOST, discovery, life_models, local
from test_discovery import coap as codec

products = life_models.LIFE_PRODUCTS

TOKEN = b"\x21\x43\x65\x87\x09\xba\xdc\xfe"
PK = "a1TNKV3wr7I"
DN = "fixture-device"
REQUEST_ID = "76234"
MAC_TEXT = "12:34:56:78:9a:bc"
IDENTITY = codec.LocalIdentity(HOST, PK, DN, "device_info", MAC_TEXT, "fixture-fw")


def body(*, request_id=REQUEST_ID, key=PK, host=HOST, extra=None):
    data = {"productKey": key, "deviceName": DN, "ip": host, "mac": MAC_TEXT}
    data.update(extra or {})
    return {"id": request_id, "code": 200, "data": data}


def response(payload=None, *, token=TOKEN, confirmable=False, options=b"\xc1\x32"):
    # Independent wire fixture: v1, TKL=8, Content, MID=0x0203,
    # Content-Format=50, followed by a JSON representation.
    content = json.dumps(body() if payload is None else payload).encode()
    return (
        bytes([0x48 if confirmable else 0x58, 0x45, 0x02, 0x03])
        + token
        + options
        + b"\xff"
        + content
    )


def inspect_request(packet):
    """Inspect actual sent bytes independently of the production decoder."""
    if packet[:2] != b"\x58\x01":
        raise AssertionError("Expected only NON GET requests with an 8-byte token")
    token = packet[4:12]
    offset = 12
    number = 0
    parts = []
    while packet[offset] != 255:
        header = packet[offset]
        offset += 1
        delta, length = header >> 4, header & 15
        if delta >= 13 or length >= 13:
            raise AssertionError("Unexpected option in small discovery request")
        number += delta
        value = packet[offset : offset + length]
        offset += length
        if number == 11:
            parts.append(value.decode())
        elif number == 12:
            if value != b"\x32":
                raise AssertionError("Expected JSON Content-Format")
        else:
            raise AssertionError("Unexpected CoAP option")
    return token, "/" + "/".join(parts), json.loads(packet[offset + 1 :])


class CodecTests(unittest.TestCase):
    def test_request_wire_shape_and_read_only_allowlist(self):
        for mechanism, (path, method) in codec.DISCOVERY_METHODS.items():
            packet = codec.encode_discovery_request(mechanism, TOKEN, 513, REQUEST_ID)
            token, actual_path, payload = inspect_request(packet)
            self.assertEqual(token, TOKEN)
            self.assertEqual(actual_path, path)
            self.assertEqual(payload["method"], method)
            self.assertEqual(payload["params"], {})
            self.assertEqual(payload["id"], REQUEST_ID)
            self.assertEqual(packet[2:4], b"\x02\x01")
        with self.assertRaises(KeyError):
            codec.encode_discovery_request("property_set", TOKEN, 1, REQUEST_ID)

    def test_both_response_layouts_and_minimal_saved_data(self):
        decoded = codec.decode_response(response())
        identities = codec.decode_identities(
            decoded.payload, HOST, "device_info", REQUEST_ID
        )
        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0].unique_id, f"life:{PK}:{DN}")
        for data in (
            {"deviceModel": {"profile": {"prodKey": PK, "name": DN}}},
            {
                "devices": {
                    "addr": HOST,
                    "port": 5683,
                    "profile": [{"prodKey": PK, "name": DN}],
                }
            },
        ):
            payload = json.dumps({"id": REQUEST_ID, "code": 200, "data": data}).encode()
            result = codec.decode_identities(payload, HOST, "alcs", REQUEST_ID)
            self.assertEqual(len(result), 1)
            self.assertIsNone(result[0].mac)
        payload = body(
            extra={
                "token": "must-not-persist",
                "random": "private-random",
                "service": "https://untrusted.invalid/",
                "accessToken": "credential",
            }
        )
        result = codec.decode_identities(
            json.dumps(payload).encode(), HOST, "device_info", REQUEST_ID
        )[0].as_entry_data()
        self.assertTrue({"product_key", "device_name", "host"} <= result.keys())
        for forbidden in ("token", "random", "service", "accessToken", "raw"):
            self.assertNotIn(forbidden, result)

    def test_all_35_known_products_and_unknown_brand(self):
        self.assertEqual(len(products), 35)
        for key in products:
            result = codec.decode_identities(
                json.dumps(body(key=key)).encode(), HOST, "device_info", REQUEST_ID
            )
            self.assertEqual(result[0].model, products[key].model)
        result = codec.decode_identities(
            json.dumps(body(key="a1OTHERBRAND")).encode(),
            HOST,
            "device_info",
            REQUEST_ID,
        )
        self.assertEqual(result, ())

    def test_json_identity_rejection_and_address_not_followed(self):
        cases = [
            body(request_id="wrong"),
            body(host="192.0.2.99"),
            body(extra={"mac": "bad"}),
            body(extra={"deviceName": "embedded\nnewline"}),
            body(extra={"productKey": []}),
            body(extra={"ip": {}}),
            {"id": REQUEST_ID, "code": "200", "data": body()["data"]},
            {"id": REQUEST_ID, "code": 401, "data": body()["data"]},
            {"id": REQUEST_ID, "code": 200, "data": []},
            [],
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    codec.decode_identities(
                        json.dumps(value).encode(), HOST, "device_info", REQUEST_ID
                    ),
                    (),
                )
        for payload in (b"\xff", b"{", b'{"id":"x","id":"y"}', b"[" * 1100):
            self.assertEqual(
                codec.decode_identities(payload, HOST, "device_info", REQUEST_ID), ()
            )

    def test_coap_malformed_packets_and_fragment_rejection(self):
        valid = response()
        invalid = [
            b"",
            b"\x58",
            valid[:3],
            valid[:11],
            b"\x98" + valid[1:],  # Wrong version.
            b"\x59" + valid[1:],  # Token longer than 8 bytes.
            b"\x68" + valid[1:],  # ACK to a NON request.
            valid[:1] + b"\x84" + valid[2:],  # 4.xx error.
            valid[:12] + b"\xd0",  # Missing extended delta.
            valid[:12] + b"\x0e\x00",  # Missing extended length.
            valid[:12] + b"\xf0",  # Reserved option nibble.
            valid[:12] + b"\x1cshort",  # Truncated value.
            valid[:12] + b"\xff",  # Empty marked payload.
            response(options=b"\xc1\x2a"),  # Unsupported representation.
            response(options=b"\xd1\x0a\x08"),  # Block2, more blocks.
            response(options=b"\xd1\x0a\x10"),  # Block2, nonzero block number.
            b"x" * (codec.MAX_DATAGRAM + 1),
        ]
        for packet in invalid:
            with self.subTest(packet=packet[:16]):
                self.assertIsNone(codec.decode_response(packet))
        rng = random.Random(352)
        for _ in range(500):
            codec.decode_response(rng.randbytes(rng.randrange(0, 100)))

    def test_confirmable_reply_ack_is_empty_and_matches_mid(self):
        decoded = codec.decode_response(response(confirmable=True))
        self.assertTrue(decoded.confirmable)
        self.assertEqual(codec.encode_ack(decoded), b"\x60\x00\x02\x03")


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def receiver(self, **kwargs):
        p = local._CoapDiscoveryProtocol(
            {},
            asyncio.Event(),
            kwargs.pop("excluded", frozenset()),
            kwargs.pop("host", HOST),
            kwargs.pop("mac", MAC_TEXT),
            **kwargs,
        )
        p.transport = Mock()
        p.requests[TOKEN] = ("device_info", REQUEST_ID)
        return p

    async def test_token_port_host_mac_and_configured_filters(self):
        for packet, peer in (
            (response(token=b"87654321"), (HOST, 5683)),
            (response(), (HOST, 11530)),
            (response(), ("192.0.2.124", 5683)),
            (response(body(extra={"mac": "12:34:56:78:9a:bd"})), (HOST, 5683)),
        ):
            receiver = self.receiver()
            receiver.datagram_received(packet, peer)
            self.assertFalse(receiver.found.is_set())
        for excluded in ({IDENTITY.unique_id}, {MAC_TEXT}):
            receiver = self.receiver(excluded=frozenset(excluded))
            receiver.datagram_received(response(), (HOST, 5683))
            self.assertFalse(receiver.found.is_set())

    async def test_required_identity_does_not_finish_on_a_different_device(self):
        receiver = self.receiver(required_identity=f"life:{PK}:different")
        receiver.datagram_received(response(), (HOST, 5683))
        self.assertFalse(receiver.found.is_set())
        self.assertEqual(receiver.results, {})

    async def test_scan_sends_both_read_only_mechanisms_and_correlated_ack(self):
        receiver = self.receiver(host=None, mac=None)
        receiver.send_round(local.ScanInterface("192.0.2.1", "192.0.2.255"))
        calls = receiver.transport.sendto.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            {c.args[1] for c in calls}, {("192.0.2.255", 5683), ("224.0.1.187", 5683)}
        )
        self.assertEqual(
            {inspect_request(c.args[0])[1] for c in calls},
            {"/sys/device/info/get", "/dev/core/service/dev"},
        )
        receiver.datagram_received(response(confirmable=True), (HOST, 5683))
        self.assertTrue(receiver.found.is_set())
        self.assertEqual(
            receiver.transport.sendto.call_args.args[0], b"\x60\x00\x02\x03"
        )

    async def test_enabled_ha_interfaces_only(self):
        network = SimpleNamespace(
            async_get_adapters=AsyncMock(
                return_value=[
                    {
                        "enabled": False,
                        "ipv4": [{"address": "10.0.0.1", "network_prefix": 24}],
                    },
                    {
                        "enabled": True,
                        "ipv4": [
                            {"address": "192.0.2.2", "network_prefix": 23},
                            {"address": "127.0.0.1", "network_prefix": 8},
                        ],
                    },
                ]
            )
        )
        components = ModuleType("homeassistant.components")
        components.network = network
        with patch.dict(sys.modules, {"homeassistant.components": components}):
            actual = await local.async_scan_interfaces(Mock())
        self.assertEqual(actual, (local.ScanInterface("192.0.2.2", "192.0.3.255"),))

    async def test_race_continues_after_empty_or_failed_legacy(self):
        async def modern():
            await asyncio.sleep(0)
            return (IDENTITY,)

        async def empty():
            return ()

        async def failed():
            raise discovery.DiscoveryError

        for legacy in (empty, failed):
            result = await local._race_discovery(legacy(), modern())
            self.assertEqual(result, (IDENTITY,))

    async def test_race_prefers_legacy_and_cancels_unrelated_wait(self):
        legacy_result = discovery.DiscoveryResult(HOST, MAC_TEXT, 0xF1, 2, AUTH)

        async def legacy():
            return (legacy_result,)

        async def modern():
            return (IDENTITY,)

        self.assertEqual(
            await local._race_discovery(legacy(), modern()), (legacy_result,)
        )
        cancelled = asyncio.Event()

        async def slow():
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with patch.object(local, "_SETTLE_SECONDS", 0.001):
            result = await local._race_discovery(legacy(), slow())
        self.assertEqual(result, (legacy_result,))
        self.assertTrue(cancelled.is_set())

    async def test_manual_legacy_probe_uses_enabled_interface_broadcasts(self):
        legacy_result = discovery.DiscoveryResult(HOST, MAC_TEXT, 0xF1, 2, AUTH)
        interfaces = (
            local.ScanInterface("192.0.2.1", "192.0.2.255"),
            local.ScanInterface("198.51.100.1", "198.51.100.255"),
        )
        with (
            patch.object(
                local,
                "async_discover_legacy_device",
                AsyncMock(return_value=legacy_result),
            ) as legacy,
            patch.object(
                local, "async_discover_coap_devices", AsyncMock(return_value=())
            ) as modern,
        ):
            result = await local.async_discover_device(
                HOST, MAC_TEXT, (2,), interfaces=interfaces
            )
        self.assertEqual(result, legacy_result)
        self.assertEqual(
            legacy.await_args.kwargs["broadcast_targets"],
            ("192.0.2.255", "198.51.100.255"),
        )
        self.assertEqual(modern.await_args.kwargs["host"], HOST)
        self.assertEqual(modern.await_args.kwargs["interfaces"], interfaces)


class _LoopbackDevice(asyncio.DatagramProtocol):
    """A small independent wire server; never sends to a LAN address."""

    def __init__(self, *, respond=True, ignore_first_round=False):
        self.transport = None
        self.respond = respond
        self.ignore_first_round = ignore_first_round
        self.requests = []
        self.seen = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        token, path, payload = inspect_request(data)
        self.requests.append((path, payload))
        self.seen.set()
        if not self.respond or (self.ignore_first_round and len(self.requests) <= 2):
            return
        if path == "/sys/device/info/get":
            result = body(request_id=payload["id"], host="127.0.0.1")
        else:
            result = {
                "id": payload["id"],
                "code": 200,
                "data": {"deviceModel": {"profile": {"prodKey": PK, "name": DN}}},
            }
        # First send a mismatching token, then the genuine response.
        self.transport.sendto(response(result, token=b"badtoken"), peer)
        self.transport.sendto(response(result, token=token), peer)


class LoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def run_server(self, device, action):
        loop = asyncio.get_running_loop()
        server, _ = await loop.create_datagram_endpoint(
            lambda: device, local_addr=("127.0.0.1", 0)
        )
        port = server.get_extra_info("sockname")[1]
        opened = []
        original = loop.create_datagram_endpoint

        async def tracked(*args, **kwargs):
            transport, protocol = await original(*args, **kwargs)
            opened.append(transport)
            return transport, protocol

        try:
            with (
                patch.object(local, "COAP_PORT", port),
                patch.object(local, "_SETTLE_SECONDS", 0.005),
                patch.object(loop, "create_datagram_endpoint", side_effect=tracked),
            ):
                await action()
            self.assertTrue(opened)
            self.assertTrue(all(t.is_closing() for t in opened))
        finally:
            server.close()

    async def test_actual_udp_requests_replies_retry_and_socket_close(self):
        device = _LoopbackDevice(ignore_first_round=True)

        async def action():
            with self.assertLogs(local.__name__, "DEBUG") as captured:
                results = await local.async_discover_coap_devices(
                    interfaces=(local.ScanInterface("127.0.0.1", "127.255.255.255"),),
                    host="127.0.0.1",
                    response_timeout=0.3,
                    retry_interval=0.02,
                )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].product_key, PK)
            self.assertEqual(results[0].mac, MAC_TEXT)
            self.assertGreaterEqual(len(device.requests), 4)
            self.assertEqual(
                {p for p, _ in device.requests},
                {"/sys/device/info/get", "/dev/core/service/dev"},
            )
            logs = "\n".join(captured.output)
            self.assertIn("request_token", logs)
            for private in (DN, MAC_TEXT, "127.0.0.1"):
                self.assertNotIn(private, logs)

        await self.run_server(device, action)

    async def test_no_reply_timeout_and_cancellation_close_sockets(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                device = _LoopbackDevice(respond=False)

                async def action(device=device, cancel=cancel):
                    task = asyncio.create_task(
                        local.async_discover_coap_devices(
                            interfaces=(
                                local.ScanInterface("127.0.0.1", "127.255.255.255"),
                            ),
                            host="127.0.0.1",
                            response_timeout=0.05,
                            retry_interval=0.02,
                        )
                    )
                    await asyncio.wait_for(device.seen.wait(), 1)
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        self.assertEqual(await task, ())

                await self.run_server(device, action)


if __name__ == "__main__":
    unittest.main()
