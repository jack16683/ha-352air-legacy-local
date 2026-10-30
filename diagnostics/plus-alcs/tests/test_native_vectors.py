"""New runtime codec compared with saved outputs of the actual APK emulator."""

import json
import unittest
from pathlib import Path

from plus_testkit.model import PLUS_KEY, Access, Identity, ServerKey
from plus_testkit.protocol import Session, auth_body


class NativeVectorTests(unittest.TestCase):
    def setUp(self):
        self.v = json.loads(
            (Path(__file__).parent / "fixtures/native-vectors.json").read_text()
        )
        self.access = Access(
            Identity(PLUS_KEY, "synthetic-device"),
            "synthetic-access",
            "synthetic-token",
        )

    def test_auth_proof_and_options_match_original_native_request(self):
        native = self.v["native_auth_request"]
        built = json.loads(
            auth_body(self.access, native["params"]["randomKey"], native["id"])
        )
        self.assertEqual(built["params"]["sign"], native["params"]["sign"])
        self.assertEqual(built["params"]["opt"], native["params"]["opt"])
        self.assertEqual(built["method"], native["method"])

    def test_read_ciphertext_session_and_sequence_options_match_native(self):
        s = Session(
            self.access,
            0x12345678,
            bytes.fromhex(self.v["synthetic_session_key_hex"]),
            7,
            17,
        )
        payload, options = s.read_payload(2)
        self.assertEqual(payload.hex(), self.v["native_read_request"]["ciphertext_hex"])
        self.assertEqual(
            [[n, b.hex()] for n, b in sorted(options)],
            self.v["native_read_request"]["options"],
        )

    def test_setup_payload_is_exact_single_target_server_auth_config(self):
        from plus_testkit.primitives import decrypt

        s = Session(
            self.access,
            0x12345678,
            bytes.fromhex(self.v["synthetic_session_key_hex"]),
            7,
            17,
        )
        body, options = s.setup_payload(
            ServerKey("NEWSYNTH", "new-synthetic-secret"), 23
        )
        obj = json.loads(decrypt(body, s.key))
        self.assertEqual(obj["method"], "core.service.setup")
        self.assertEqual(set(obj["params"]), {"configType", "configValue"})
        self.assertEqual(obj["params"]["configType"], "ServerAuthInfo")
        self.assertEqual(len(obj["params"]["configValue"]), 1)
        self.assertEqual(
            obj["params"]["configValue"][0]["deviceName"], self.access.identity.name
        )
