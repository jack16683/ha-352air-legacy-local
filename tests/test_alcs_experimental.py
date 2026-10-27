# SPDX-License-Identifier: GPL-3.0-or-later
"""Experimental ALCS tests against a synthetic loopback device only."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

importlib.import_module("cryptography.hazmat.primitives.ciphers")
PACKAGE = "_alcs_experimental_tests_352"
root = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = ModuleType(PACKAGE)
package.__path__ = [str(root)]
protocols = ModuleType(f"{PACKAGE}.protocols")
protocols.__path__ = [str(root / "protocols")]
with patch.dict(sys.modules, {PACKAGE: package, f"{PACKAGE}.protocols": protocols}):
    alcs = importlib.import_module(f"{PACKAGE}.protocols.alcs_experimental")

TOKEN = "synthetic-token"
ACCESS = "synthetic-access-key"
NAME = "synthetic-device"
SERVER_RANDOM = "ABCDEFGHIJKLMNO"
SID = 0x12345678


class SimulatedDevice(asyncio.DatagramProtocol):
    def __init__(self, *, auth_proof=True, confirm=True):
        self.power = 0
        self.writes = 0
        self.auth_proof = auth_proof
        self.confirm = confirm
        self.key = None
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet, source):
        kind, code, mid, token, opts, body = alcs.decode(packet)
        if (kind, code) != (0, 1):
            return
        path = b"/" + b"/".join(opts.get(11, []))
        if path.endswith(b"/core/service/auth"):
            request = json.loads(body)
            params = request["params"]
            expected = base64.b64encode(
                hmac.new(
                    TOKEN.encode(), params["randomKey"].encode(), hashlib.sha1
                ).digest()
            ).decode()
            if params["accessKey"] != ACCESS or params["sign"] != expected:
                return
            self.key = hmac.new(
                TOKEN.encode(),
                (params["randomKey"] + SERVER_RANDOM).encode(),
                hashlib.sha1,
            ).digest()
            proof = base64.b64encode(
                hmac.new(
                    TOKEN.encode(), SERVER_RANDOM.encode() + b"\0", hashlib.sha1
                ).digest()
            ).decode()
            if not self.auth_proof:
                proof = "invalid"
            result = {
                "id": request["id"],
                "code": 200,
                "data": {
                    "randomKey": SERVER_RANDOM,
                    "sign": proof,
                    "sessionId": SID,
                    "opt": 1,
                },
            }
            options = [(12, b"\x32")]
            payload = json.dumps(result).encode()
        else:
            if self.key is None or int.from_bytes(opts[71][0], "big") != SID:
                return
            request = json.loads(alcs.decrypt(body, self.key))
            if path.endswith(b"/thing/service/property/set"):
                self.writes += 1
                if self.confirm:
                    self.power = request["params"]["PowerSwitch"]
                data = {}
            elif path.endswith(b"/thing/service/property/get"):
                data = {"PowerSwitch": self.power}
            else:
                return
            result = {"id": request["id"], "code": 200, "data": data}
            options = [(12, b"\x2a"), (71, SID.to_bytes(4, "big"))]
            payload = alcs.encrypt(json.dumps(result).encode(), self.key)
        response = bytearray(alcs.encode(mid, token, "/", payload, options))
        response[0] = 0x68  # Piggybacked ACK, same token and message ID.
        response[1] = 69
        self.transport.sendto(response, source)


class CodecTests(unittest.TestCase):
    def test_encryption_matches_independent_openssl_blocks(self):
        result = alcs.encrypt(b"0123456789ABCDEF", b"0123456789abcdef")
        self.assertEqual(
            result.hex(),
            "701b595dbe720734d6b201882cf527ea5a9b7cc58ee937a240657227ec4b7888",
        )

    def test_cipher_roundtrip_and_reject_bad_padding(self):
        key = b"0123456789abcdefghij"
        for length in (1, 15, 16, 17, 31, 32, 127):
            with self.subTest(length=length):
                data = bytes(range(length))
                ciphertext = alcs.encrypt(data, key)
                self.assertEqual(alcs.decrypt(ciphertext, key), data)
        with self.assertRaises(ValueError):
            alcs.decrypt(bytes(17), key)

    def test_only_plus_credentials_and_no_secret_repr(self):
        credentials = alcs.Credentials(alcs.PLUS_KEY, NAME, ACCESS, TOKEN)
        self.assertNotIn(TOKEN, repr(credentials))
        with self.assertRaises(ValueError):
            alcs.Credentials("wrong-product", NAME, ACCESS, TOKEN)
        with self.assertRaises(ValueError):
            alcs.Credentials(alcs.PLUS_KEY, "../not-a-device", ACCESS, TOKEN)


class PowerTests(unittest.IsolatedAsyncioTestCase):
    async def make_client(self, **device_options):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SimulatedDevice(**device_options), local_addr=("127.0.0.1", 0)
        )
        self.addCleanup(transport.close)
        client = alcs.ExperimentalPowerClient(
            "192.0.2.123",
            alcs.Credentials(alcs.PLUS_KEY, NAME, ACCESS, TOKEN),
            timeout=0.1,
        )
        client._host = "127.0.0.1"
        client._port = transport.get_extra_info("sockname")[1]
        return client, protocol

    async def test_authenticated_read_write_and_readback(self):
        client, device = await self.make_client()
        self.assertFalse(await client.read())
        self.assertTrue(await client.set_power(True))
        self.assertEqual(device.writes, 1)
        self.assertTrue(await client.read())
        self.assertTrue(await client.set_power(True))
        self.assertEqual(device.writes, 1)

    async def test_bad_proof_never_writes(self):
        client, device = await self.make_client(auth_proof=False)
        with self.assertRaises(alcs.AlcsError):
            await client.set_power(True)
        self.assertEqual(device.writes, 0)

    async def test_unconfirmed_write_is_unknown_and_not_retried(self):
        client, device = await self.make_client(confirm=False)
        with self.assertRaises(alcs.AlcsOutcomeUnknown):
            await client.set_power(True)
        self.assertEqual(device.writes, 1)


if __name__ == "__main__":
    unittest.main()
