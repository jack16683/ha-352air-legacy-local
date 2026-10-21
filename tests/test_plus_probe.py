"""Independent CoAP wire fixtures and loopback-only Plus diagnostic checks."""

import ast
import contextlib
import importlib.util
import io
import json
import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/352_plus_probe.py"
spec = importlib.util.spec_from_file_location("plus_probe_test", SCRIPT)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
SECRET = "DO_NOT_PUBLISH_THIS_SECRET"
DN = "DEVICE_FIXTURE_12"
TARGET = "192.0.2.123"


def incoming_request(packet):
    assert packet[1] == 1, "Only GET is allowed"
    n = packet[0] & 15
    offset, number, options = 4 + n, 0, {}
    while offset < len(packet) and packet[offset] != 255:
        h = packet[offset]
        offset += 1

        def field(x):
            nonlocal offset
            if x < 13:
                return x
            length = 1 if x == 13 else 2
            value = int.from_bytes(packet[offset : offset + length], "big")
            offset += length
            return value + (13 if x == 13 else 269)

        delta, size = field(h >> 4), field(h & 15)
        number += delta
        options.setdefault(number, []).append(packet[offset : offset + size])
        offset += size
    payload = packet[offset + 1 :] if offset < len(packet) else b""
    return {
        "mid": int.from_bytes(packet[2:4], "big"),
        "token": packet[4 : 4 + n],
        "path": "/" + "/".join(x.decode() for x in options.get(11, [])),
        "body": json.loads(payload) if payload else None,
        "options": options,
    }


def response(request, body=b"", code=69, kind=1, options=None, token=None, mid=None):
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    if isinstance(body, str):
        body = body.encode()
    t = request["token"] if token is None else token
    m = request["mid"] if mid is None else mid
    out = bytearray(bytes([0x40 | kind << 4 | len(t), code]) + struct.pack("!H", m) + t)
    previous = 0
    for number, value in sorted((options or {}).items()):
        assert number - previous < 13 and len(value) < 13
        out.extend(bytes([(number - previous) << 4 | len(value)]) + value)
        previous = number
    return bytes(out) + (b"\xff" + body if body else b"")


def info(req):
    return {
        "id": req["body"]["id"],
        "code": 200,
        "data": {
            "productKey": p.PLUS_KEY,
            "deviceName": DN,
            "mac": "12:34:56:78:9a:bc",
            "ip": TARGET,
            "fwVersion": "1.6.3_EMC3080P",
            "cipherType": 3,
            "service": 5,
            "type": 0,
            "tokenType": 1,
            "token": SECRET,
            "awssVer": {"smartconfig": "2.0", "softap": "2.0"},
        },
    }


class Server:
    def __init__(self, handler):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.errors = []
        self.requests = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.done.set()
        self.thread.join(1)
        self.sock.close()
        if self.errors:
            raise self.errors[0]

    def serve(self):
        while not self.done.is_set():
            try:
                data, peer = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            if data[:2] == b"\x60\x00":
                continue
            try:
                req = incoming_request(data)
                self.requests.append(req)
                packets = self.handler(req)
                for packet in packets:
                    self.sock.sendto(packet, peer)
            except Exception as exc:
                self.errors.append(exc)
                return


class FormatTests(unittest.TestCase):
    def test_python38_and_extended_uri_segments(self):
        ast.parse(SCRIPT.read_text(), feature_version=(3, 8))
        path = "/sys/" + p.PLUS_KEY + "/" + "a" * 64 + "/thing/service/property/get"
        body = {
            "id": "1",
            "version": "1.0",
            "method": p.READ_METHOD,
            "params": list(p.READ_KEYS),
        }
        wire = p.encode_get(path, b"12345678", 10, body, accept=50, block=0)
        req = incoming_request(wire)
        self.assertEqual(req["path"], path)
        self.assertEqual(req["body"], body)
        self.assertEqual(req["options"][17], [b"2"])
        self.assertEqual(req["options"][23], [b""])

    def test_metadata_retained_without_identity_credentials_or_unknown_text(self):
        payload = info({"body": {"id": "1"}})
        payload["data"][SECRET] = {"unrecognized": SECRET, "number": 123456789}
        payload["data"]["PowerSwitch"] = {"value": 0, "time": 123456789}
        payload["data"]["msg"] = "invalid accessToken " + SECRET
        safe = p.safe_json(payload)
        text = json.dumps(safe)
        for secret in (SECRET, DN, TARGET, "12:34:56:78:9a:bc"):
            self.assertNotIn(secret, text)
        self.assertEqual(safe["data"]["service"], 5)
        self.assertEqual(safe["data"]["cipherType"], 3)
        self.assertEqual(safe["data"]["awssVer"]["softap"], "2.0")
        self.assertEqual(safe["data"]["PowerSwitch"]["value"], 0)
        self.assertEqual(safe["data"]["msg"]["categories"], ["auth", "request"])
        self.assertFalse(p.scalar(10**1000))
        self.assertFalse(p.scalar(float("nan")))
        self.assertFalse(p.scalar(True))

    def test_metadata_malformed_types_do_not_crash(self):
        for key in ("method", "identifier", "pal", "service", "fwVersion"):
            for value in ([], {}, True, 10**1000, None, [{}]):
                p.safe_json({key: value})

    def test_wrong_identity_and_json_correlation_are_rejected(self):
        result = {"coap_code": "2.05", "json_id_matches": True}
        body = info({"body": {"id": "1"}})
        self.assertEqual(p.identity_from(result, body, TARGET), (p.PLUS_KEY, DN))
        for key, value in [
            ("deviceName", "../../set"),
            ("ip", "192.0.2.124"),
            ("productKey", "other"),
            ("mac", "bad"),
        ]:
            mutated = json.loads(json.dumps(body))
            mutated["data"][key] = value
            self.assertIsNone(p.identity_from(result, mutated, TARGET))
        self.assertIsNone(
            p.identity_from(dict(result, json_id_matches=False), body, TARGET)
        )

    def test_state_requires_response_success_and_valid_power(self):
        result = {"coap_code": "2.05", "json_id_present": True, "json_id_matches": True}
        for value in (0, 1):
            self.assertEqual(
                p.properties_from(
                    result, {"code": 200, "data": {"PowerSwitch": {"value": value}}}
                ),
                {"PowerSwitch": value},
            )
        for value in (True, 2, -1, 1.0, SECRET, {}, float("nan")):
            self.assertEqual(
                p.properties_from(
                    result, {"code": 200, "data": {"PowerSwitch": value}}
                ),
                {},
            )
        self.assertEqual(
            p.properties_from(
                dict(result, json_id_matches=False),
                {"code": 200, "data": {"PowerSwitch": 1}},
            ),
            {},
        )

    def test_resource_directory_never_follows_writes_foreign_hosts_or_queries(self):
        identity = (p.PLUS_KEY, DN)
        read = "/sys/" + p.PLUS_KEY + "/" + DN + "/thing/service/property/get"
        data = (
            f'<{read}>;ct="0 50";rt="core.r",<{read[:-3]}set>,'
            f"<coap://192.0.2.9{read}>,<{read}?token={SECRET}>,<coaps:{read}>,"
            f'</{SECRET}>;title="comma, value"'
        )
        result, follow = p.core_summary(data, identity, TARGET)
        self.assertEqual(follow, {read})
        self.assertEqual(len(result["entries"]), 6)
        for secret in (DN, TARGET, SECRET, "192.0.2.9"):
            self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["entries"][0]["content_formats"], [0, 50])

    def test_block_assembly_and_missing_later_content_format(self):
        b = p.Blocks()
        first = {
            "code": 69,
            "options": {4: b"e", 12: b"", 23: b"\x08"},
            "payload": b"x" * 16,
        }
        self.assertEqual(b.add(first), 16)
        self.assertEqual(b.add(first), "duplicate")
        last = {"code": 69, "options": {4: b"e", 23: b"\x10"}, "payload": b"last"}
        self.assertIsNone(b.add(last))
        self.assertEqual(bytes(b.parts), b"x" * 16 + b"last")

    def test_block_rejects_gaps_mixed_representation_bad_size_and_limits(self):
        first = {"code": 69, "options": {4: b"e", 23: b"\x08"}, "payload": b"x" * 16}
        for other in (
            {"code": 69, "options": {4: b"e", 23: b"\x20"}, "payload": b"x"},
            {"code": 69, "options": {4: b"f", 23: b"\x10"}, "payload": b"x"},
            {"code": 132, "options": {4: b"e", 23: b"\x10"}, "payload": b"x"},
            {"code": 69, "options": {4: b"e"}, "payload": b"x"},
        ):
            b = p.Blocks()
            b.add(first)
            with self.assertRaises(ValueError):
                b.add(other)
        with self.assertRaises(ValueError):
            p.Blocks().add({"code": 69, "options": {23: b"\x08"}, "payload": b"x"})
        with patch.object(p, "MAX_BYTES", 8), self.assertRaises(ValueError):
            p.Blocks().add(first)

    def test_malformed_coap_rejected(self):
        for packet in (
            b"",
            b"\x49\x45\x00\x01",
            b"\x40\x45\x00\x01\xff",
            b"\x40\x45\x00\x01\xf0",
            b"\x40\x45\x00\x01\xc1",
        ):
            with self.assertRaises(ValueError):
                p.decode(packet)


class WireTests(unittest.TestCase):
    def exchange(self, handler, **kwargs):
        with Server(handler) as server:
            client = p.Client("127.0.0.1", timeout=0.06, port=server.port)
            try:
                return client.request(
                    "fixture", p.INFO_PATH, "device.info.get", {}, **kwargs
                )
            finally:
                client.close()

    def test_empty_ack_then_separate_response_and_unmatched_token(self):
        def handler(req):
            return [
                response(req, code=0, kind=2, token=b""),
                response(req, info(req), token=b"badtoken"),
                response(
                    req,
                    info(req),
                    kind=0,
                    mid=(req["mid"] + 1) % 65536,
                    options={12: b""},
                ),
            ]

        result, body = self.exchange(handler)
        self.assertEqual(result["empty_acks"], 1)
        self.assertTrue(result["json_id_matches"])
        self.assertEqual(body["data"]["productKey"], p.PLUS_KEY)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_piggyback_ack_response(self):
        result, _ = self.exchange(lambda r: [response(r, info(r), kind=2)])
        self.assertEqual(result["coap_code"], "2.05")

    def test_reset_and_ack_only_timeout_are_distinct(self):
        for kind, status in ((3, "reset"), (2, "timeout")):
            result, _ = self.exchange(
                lambda r, kind=kind: [response(r, code=0, kind=kind, token=b"")]
            )
            self.assertEqual(result["status"], status)
            self.assertFalse(result["body_complete"])

    def test_404_and_authorization_body_are_reported_without_secret(self):
        for code, text in ((132, "4.04"), (129, "4.01"), (131, "4.03"), (128, "4.00")):
            result, _ = self.exchange(
                lambda r, code=code: [
                    response(
                        r,
                        {
                            "id": r["body"]["id"],
                            "code": 401,
                            "message": "bad token " + SECRET,
                        },
                        code=code,
                    )
                ]
            )
            self.assertEqual(result["coap_code"], text)
            self.assertEqual(result["application_code"], 401)
            self.assertNotIn(SECRET, json.dumps(result))

    def test_block2_real_udp_uses_same_request_and_contiguous_blocks(self):
        saved = {}

        def handler(req):
            body = saved.setdefault("body", json.dumps(info(req)).encode())
            block = int.from_bytes(req["options"].get(23, [b""])[0], "big")
            number = block >> 4
            size = 64
            part = body[number * size : (number + 1) * size]
            more = (number + 1) * size < len(body)
            value = (number << 4) | (8 if more else 0) | 2
            return [
                response(
                    req,
                    part,
                    options={4: b"etag", 12: b"", 23: value.to_bytes(2, "big")},
                )
            ]

        result, body = self.exchange(handler)
        self.assertTrue(result["body_complete"])
        self.assertGreater(result["blocks"], 1)
        self.assertEqual(body["data"]["deviceName"], DN)
        self.assertTrue(result["json_id_matches"])

    def test_wrong_mid_ack_is_not_accepted(self):
        result, _ = self.exchange(
            lambda r: [response(r, info(r), kind=2, mid=(r["mid"] + 1) % 65536)]
        )
        self.assertEqual(result["status"], "timeout")

    def test_stale_ack_does_not_suppress_retry_for_next_block(self):
        saved = {"second_seen": 0}

        def handler(req):
            if "body" not in saved:
                saved["body"] = json.dumps(info(req)).encode() + b" " * 512
                saved["first_mid"] = req["mid"]
            value = int.from_bytes(req["options"].get(23, [b""])[0], "big")
            number = value >> 4
            if number == 1:
                saved["second_seen"] += 1
                if saved["second_seen"] == 1:
                    return [
                        response(req, code=0, kind=2, token=b"", mid=saved["first_mid"])
                    ]
                self.assertNotEqual(req["mid"], saved["first_mid"])
            body = saved["body"]
            part = body[number * 512 : (number + 1) * 512]
            more = (number + 1) * 512 < len(body)
            block = (number << 4) | (8 if more else 0) | 5
            return [response(req, part, options={12: b"", 23: bytes([block])})]

        result, body = self.exchange(handler)
        self.assertTrue(result["body_complete"])
        self.assertEqual(saved["second_seen"], 2)
        self.assertEqual(body["code"], 200)

    def full_run(self, property_code=69, identity_ok=True, interactive=False):
        powers = iter([0, 0, 0, 0, 1, 0])
        sent = []

        def handler(req):
            sent.append(req)
            if req["path"] == p.INFO_PATH:
                body = info(req)
                if not identity_ok:
                    body["data"]["productKey"] = "other"
                return [response(req, body)]
            if req["path"] == p.CORE_PATH:
                return [
                    response(
                        req,
                        "</sys/"
                        + p.PLUS_KEY
                        + "/"
                        + DN
                        + "/thing/service/property/set>",
                        69,
                        options={12: b"("},
                    )
                ]
            if req["path"] == p.ALCS_PATH:
                return [response(req, code=132)]
            assert req["path"].endswith("/thing/service/property/get")
            assert req["body"]["method"] == p.READ_METHOD
            body = {
                "id": req["body"]["id"],
                "code": 200 if property_code == 69 else 401,
                "data": {"PowerSwitch": next(powers, 0), "WindSpeed": 2},
                "message": SECRET,
            }
            return [response(req, body, code=property_code)]

        original = p.Client
        with (
            Server(handler) as server,
            patch.object(
                p,
                "Client",
                side_effect=lambda target: original(
                    "127.0.0.1", timeout=0.06, port=server.port
                ),
            ),
            patch.object(p.sys.stdin, "isatty", return_value=interactive),
            patch.object(p.time, "sleep", return_value=None),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            report = p.run(TARGET, 45 if interactive else 0)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertNotIn(DN, json.dumps(report))
        self.assertNotIn(TARGET, json.dumps(report))
        return report, sent

    def test_real_udp_full_flow_remains_get_only_and_observes_change_return(self):
        report, sent = self.full_run(interactive=True)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["observation"]["status"], "change_and_return_observed")
        self.assertTrue(report["provisioning_flags"]["offline_log"])
        self.assertFalse(report["provisioning_flags"]["offline_ota"])
        self.assertFalse(any(r["path"].endswith("/set") for r in sent))

    def test_missing_identity_blocks_all_device_specific_reads(self):
        report, sent = self.full_run(identity_ok=False)
        self.assertEqual(
            report["property_reads_skipped"], "no_correlated_plus_identity"
        )
        self.assertFalse(any("/property/" in r["path"] for r in sent))

    def test_auth_error_skips_manual_window_and_selects_next_step(self):
        report, _ = self.full_run(property_code=129, interactive=True)
        self.assertEqual(report["observation"]["status"], "skipped_no_power_read")
        self.assertIn("authorization", report["next_step"])


if __name__ == "__main__":
    unittest.main()
