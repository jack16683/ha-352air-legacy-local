"""Narrow ALCS operations: identity, auth, PowerSwitch GET and one-key setup."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field

from . import primitives as wire
from .model import Access, ProbeError, power_value


def object_json(payload):
    if len(payload) > 16384:
        raise ProbeError("BODY_LIMIT")
    try:
        return wire._object(payload)
    except Exception:
        raise ProbeError("INVALID_JSON") from None


def auth_body(access, nonce, request_id):
    if not re.fullmatch(r"[A-Za-z0-9]{15}", nonce):
        raise ProbeError("NONCE_INVALID")
    proof = base64.b64encode(
        hmac.digest(access.token.encode(), nonce.encode(), "sha1")
    ).decode()
    return wire.json.dumps(
        {
            "version": "1.0",
            "method": "core/service/auth",
            "id": request_id,
            "params": {
                "prodKey": access.identity.product,
                "deviceName": access.identity.name,
                "encrypt": "payload",
                "randomKey": nonce,
                "sign": proof,
                "accessKey": access.key,
                "opt": 7,
            },
        },
        separators=(",", ":"),
    ).encode()


@dataclass(repr=False)
class Session:
    access: Access = field(repr=False)
    sid: int
    key: bytes = field(repr=False)
    opt: int
    seq: int

    @classmethod
    def authenticate(cls, payload, access, nonce, request_id):
        obj = object_json(payload)
        if str(obj.get("id")) != str(request_id):
            raise ProbeError("JSON_ID_MISMATCH")
        if type(obj.get("code")) is not int or obj["code"] != 200:
            raise ProbeError("AUTH_REJECTED", application_code=obj.get("code"))
        data = obj.get("data")
        if not isinstance(data, dict):
            raise ProbeError("SESSION_INVALID")
        server, sid, opt, seq = (
            data.get("randomKey"),
            data.get("sessionId"),
            data.get("opt", 1),
            data.get("seqStart", 0),
        )
        if not isinstance(server, str) or not re.fullmatch(r"[A-Za-z0-9]{15}", server):
            raise ProbeError("NONCE_UNSUPPORTED")
        if type(sid) is not int or not 1 <= sid <= 0xFFFFFFFF:
            raise ProbeError("SESSION_INVALID")
        if type(opt) is not int or opt not in (1, 5, 7):
            raise ProbeError("SESSION_OPTIONS_UNSUPPORTED")
        if (
            type(seq) is not int
            or not 0 <= seq <= 0xFFFFFFFF
            or (opt & 2 and "seqStart" not in data)
        ):
            raise ProbeError("SEQUENCE_INVALID")
        expected = base64.b64encode(
            hmac.digest(access.token.encode(), server.encode() + b"\0", "sha1")
        ).decode()
        if not isinstance(data.get("sign"), str) or not hmac.compare_digest(
            expected, data["sign"]
        ):
            raise ProbeError("SERVER_PROOF_INVALID")
        key = hmac.digest(access.token.encode(), (nonce + server).encode(), "sha1")
        return cls(access, sid, key, opt, seq)

    def _protect(self, payload):
        sid = (
            self.sid.to_bytes(4, "big")
            if self.opt & 4
            else self.sid.to_bytes((self.sid.bit_length() + 7) // 8, "big")
        )
        if self.opt & 4:
            sid += hashlib.md5(payload).digest()[:4]
        options = [(12, b"\x2a"), (71, sid)]
        if self.opt & 2:
            if self.seq == 0xFFFFFFFF:
                raise ProbeError("SEQUENCE_EXHAUSTED")
            seq = self.seq.to_bytes(4, "big")
            options.append((72, seq + hmac.digest(self.key, seq, "sha1")[:4]))
            self.seq += 1
        return wire.encrypt(payload, self.key), options

    def read_payload(self, request_id):
        return self._protect(
            wire._json("thing.service.property.get", ["PowerSwitch"], request_id)
        )

    def setup_payload(self, server_key, request_id):
        # This is the only writer. No arbitrary method, config type or device list.
        identity = self.access.identity
        params = {
            "configType": "ServerAuthInfo",
            "configValue": [
                {
                    "authCode": server_key.prefix,
                    "authSecret": server_key.secret,
                    "productKey": identity.product,
                    "deviceName": identity.name,
                }
            ],
        }
        return self._protect(wire._json("core.service.setup", params, request_id))

    def reply(self, ciphertext, options, request_id):
        values = options.get(71, [])
        if len(values) != 1:
            raise ProbeError("SESSION_OPTION_INVALID")
        value = values[0]
        if self.opt & 4:
            if len(value) != 8:
                raise ProbeError("SESSION_OPTION_INVALID")
            sid = int.from_bytes(value[:4], "big")
        else:
            if not 1 <= len(value) <= 4:
                raise ProbeError("SESSION_OPTION_INVALID")
            sid = int.from_bytes(value, "big")
        if sid != self.sid:
            raise ProbeError("SESSION_MISMATCH")
        try:
            plain = wire.decrypt(ciphertext, self.key)
        except Exception:
            raise ProbeError("CIPHERTEXT_INVALID") from None
        if self.opt & 4 and not hmac.compare_digest(
            value[4:], hashlib.md5(plain).digest()[:4]
        ):
            raise ProbeError("PAYLOAD_CHECKSUM_INVALID")
        obj = object_json(plain)
        if str(obj.get("id")) != str(request_id):
            raise ProbeError("JSON_ID_MISMATCH")
        if type(obj.get("code")) is not int or obj["code"] != 200:
            raise ProbeError("APPLICATION_REJECTED", application_code=obj.get("code"))
        return obj

    def read_reply(self, ciphertext, options, request_id):
        return power_value(self.reply(ciphertext, options, request_id).get("data"))
