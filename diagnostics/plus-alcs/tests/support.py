"""Synthetic loopback device and cloud; no account service is contacted."""

import base64
import hashlib
import hmac
import json
import socket
import threading
import time

from plus_testkit import primitives as wire
from plus_testkit.model import EXPECTED_FIRMWARE, PLUS_KEY, Identity, ServerKey

IDENTITY = Identity(PLUS_KEY, "SYNTHETIC_DEVICE", EXPECTED_FIRMWARE)
OLD = ServerKey("OLDSYNTH", "old-synthetic-server-secret")
RECOVERY = {"kind": "known_local_key", **OLD.private()}
MANUAL = {
    "kind": "owner_manual",
    "procedure": "official_app_repair",
    "owner_can_execute": True,
}
ACCOUNT = "SYNTH_ACCOUNT_392714"
PASSWORD = "SYNTH_PASSWORD_502851"
PASSPHRASE = "SYNTH_VAULT_PHRASE_290714"


def encrypt_reply(plain, key, sid, opt):
    value = (
        sid.to_bytes(4, "big") + hashlib.md5(plain).digest()[:4]
        if opt & 4
        else sid.to_bytes((sid.bit_length() + 7) // 8, "big")
    )
    return wire.encrypt(plain, key), [(12, b"\x2a"), (71, value)]


class Device:
    def __init__(self, setup="normal"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.failure = None
        self.keys = {OLD.access(IDENTITY).key: OLD.access(IDENTITY).token}
        self.sessions = {}
        self.sid = 0x12340000
        self.power = 0
        self.setup = setup
        self.writes = 0
        self.requests = []
        self.fault = None
        self.silent = False
        self.firmware = EXPECTED_FIRMWARE
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def close(self):
        self.running = False
        self.thread.join(timeout=0.4)
        self.sock.close()
        if self.failure:
            raise self.failure

    def reboot(self):
        self.sessions = {}
        if self.setup == "ram_only":
            self.keys = {OLD.access(IDENTITY).key: OLD.access(IDENTITY).token}

    def loop(self):
        try:
            while self.running:
                try:
                    packet, source = self.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                self.receive(packet, source)
        except Exception as error:
            self.failure = error

    def response(self, mid, token, body, options, source, code=69):
        fault = self.fault
        self.fault = None
        if self.silent:
            return
        if fault == "bad_format":
            options = list(options) + [(12, b"\x32")]
        if fault == "block2":
            options = list(options) + [(23, b"\x00")]
        if fault == "critical_option":
            options = list(options) + [(99, b"\x00")]
        if fault == "bad_ciphertext":
            body = body[:-1] + bytes([body[-1] ^ 1])
        if fault == "bad_sid":
            options = [(n, (bytes(4) + v[4:]) if n == 71 else v) for n, v in options]
        if fault == "bad_checksum":
            options = [(n, (v[:4] + bytes(4)) if n == 71 else v) for n, v in options]
        if fault == "duplicate_session":
            options = list(options) + [(n, v) for n, v in options if n == 71]
        packet = bytearray(wire.encode(mid, token, "/", body, options))
        packet[0] = 0x68
        packet[1] = code
        if fault == "timeout":
            return
        if fault == "error_404":
            packet[1] = 132
        if fault == "reset":
            self.sock.sendto(b"\x70\x00" + mid.to_bytes(2, "big"), source)
            return
        if fault == "empty_ack_only":
            self.sock.sendto(b"\x60\x00" + mid.to_bytes(2, "big"), source)
            return
        if fault == "wrong_mid":
            wrong = bytearray(packet)
            wrong[2:4] = ((mid + 1) & 65535).to_bytes(2, "big")
            self.sock.sendto(wrong, source)
        if fault == "wrong_token":
            wrong = bytearray(packet)
            wrong[4:12] = b"BADTOKEN"
            self.sock.sendto(wrong, source)
        if fault == "rogue_source":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rogue:
                rogue.sendto(packet, source)
            time.sleep(0.01)
        if fault in {"delayed_non", "delayed_con"}:
            self.sock.sendto(b"\x60\x00" + mid.to_bytes(2, "big"), source)
            time.sleep(0.01)
            packet[0] = 0x58 if fault == "delayed_non" else 0x48
            packet[2:4] = ((mid + 7) & 65535).to_bytes(2, "big")
        self.sock.sendto(packet, source)

    def receive(self, packet, source):
        kind, code, mid, token, options, body = wire.decode(packet)
        if code == 0:
            return
        path = "/" + "/".join(v.decode() for v in options.get(11, []))
        if path == "/sys/device/info/get":
            request = json.loads(body)
            self.requests.append((code, path, request, source))
            result = {
                "id": request["id"],
                "code": 200,
                "data": {
                    "productKey": PLUS_KEY,
                    "deviceName": IDENTITY.name,
                    "fwVersion": self.firmware,
                    "ip": "127.0.0.1",
                    "token": "SYNTH_DISCOVERY_TOKEN_NOT_CONTROL",
                },
            }
            self.response(
                mid, token, json.dumps(result).encode(), [(12, b"\x32")], source
            )
            return
        if path.endswith("/core/service/auth"):
            request = json.loads(body)
            self.requests.append((code, path, request, source))
            params = request["params"]
            access_token = self.keys.get(params["accessKey"])
            if access_token is None:
                self.response(
                    mid,
                    token,
                    json.dumps(
                        {"id": request["id"], "code": 502, "message": PASSWORD}
                    ).encode(),
                    [],
                    source,
                )
                return
            proof = base64.b64encode(
                hmac.digest(access_token.encode(), params["randomKey"].encode(), "sha1")
            ).decode()
            assert proof == params["sign"]
            self.sid += 1
            server = "ABCDEFGHIJKLMNO"
            opt = 7
            key = hmac.digest(
                access_token.encode(), (params["randomKey"] + server).encode(), "sha1"
            )
            self.sessions[(source, self.sid)] = {"key": key, "opt": opt, "last": 16}
            result = {
                "id": request["id"],
                "code": 200,
                "data": {
                    "sessionId": self.sid,
                    "randomKey": server,
                    "opt": opt,
                    "seqStart": 17,
                    "sign": base64.b64encode(
                        hmac.digest(
                            access_token.encode(), server.encode() + b"\0", "sha1"
                        )
                    ).decode(),
                },
            }
            if self.fault == "bad_server_proof":
                result["data"]["sign"] = "A" * 28
                self.fault = None
            self.response(mid, token, json.dumps(result).encode(), [], source)
            return
        sid = int.from_bytes(options[71][0][:4], "big")
        session = self.sessions[(source, sid)]
        key = session["key"]
        plain = wire.decrypt(body, key)
        assert options[71][0][4:] == hashlib.md5(plain).digest()[:4]
        sequence = options[72][0]
        number = int.from_bytes(sequence[:4], "big")
        assert sequence[4:] == hmac.digest(key, sequence[:4], "sha1")[:4]
        assert number > session["last"]
        session["last"] = number
        request = json.loads(plain)
        self.requests.append((code, path, request, source))
        if path.endswith("/thing/service/property/get"):
            assert (
                code == 1
                and request["method"] == "thing.service.property.get"
                and request["params"] == ["PowerSwitch"]
            )
            result = {
                "id": request["id"],
                "code": 200,
                "data": {"PowerSwitch": self.power},
            }
            if self.fault == "wrong_json_id":
                result["id"] = "WRONG_ID"
                self.fault = None
        elif path.endswith("/core/service/setup"):
            assert code == 3 and request["method"] == "core.service.setup"
            assert request["params"]["configType"] == "ServerAuthInfo"
            entries = request["params"]["configValue"]
            assert len(entries) == 1
            entry = entries[0]
            assert (
                entry["productKey"] == PLUS_KEY and entry["deviceName"] == IDENTITY.name
            )
            self.writes += 1
            if self.setup != "ack_no_apply":
                new = ServerKey(entry["authCode"], entry["authSecret"]).access(IDENTITY)
                self.keys[new.key] = new.token
                if self.setup == "remove_old":
                    self.keys = {new.key: new.token}
            if self.setup == "drop_reply":
                return
            result = {"id": request["id"], "code": 200}
        else:
            raise AssertionError("Unexpected method or path")
        body, opts = encrypt_reply(json.dumps(result).encode(), key, sid, 7)
        self.response(mid, token, body, opts, source)


class Cloud:
    def __init__(self, device):
        self.device = device
        self.calls = []
        self.closed = False
        self.stale = False
        self.fail_after = False

    def login(self, account, password):
        assert (account, password) == (ACCOUNT, PASSWORD)
        self.calls.append("login")
        return {"status": "ok"}

    def access_for(self, identity):
        assert identity.product == PLUS_KEY and identity.name == IDENTITY.name
        self.calls.append("access")
        return OLD.access(identity)

    def select_target(self, identity):
        assert identity.product == IDENTITY.product and identity.name == IDENTITY.name
        self.calls.append("select_target")

    def snapshot(self):
        self.calls.append("snapshot")
        return {
            "status": "ok",
            "online": not (self.fail_after and self.device.writes > 0),
            "power": self.device.power,
            "sample_age_seconds": 500 if self.stale else 0,
            "fresh_sample": not self.stale,
        }

    def close(self):
        self.closed = True
