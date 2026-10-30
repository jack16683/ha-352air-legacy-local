"""Shared validation, bounded errors and sanitized report construction."""

from __future__ import annotations

import base64
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field

from .error_codes import ALLOWED_ERROR_CODES

PLUS_KEY = "a1TNKV3wr7I"
EXPECTED_FIRMWARE = "1.6.3_EMC3080P"
CLOUD_STAGES = {
    "mx_login",
    "region",
    "oa_login",
    "iot_session",
    "refresh",
    "device_list",
    "access_info",
    "status",
    "properties",
}
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class ProbeError(Exception):
    def __init__(
        self,
        code,
        *,
        application_code=None,
        coap_code=None,
        stage=None,
        http_status=None,
    ):
        if not isinstance(code, str) or code not in ALLOWED_ERROR_CODES:
            code = "INTERNAL_ERROR"
        self.code = code
        self.http_status = (
            http_status
            if type(http_status) is int and 100 <= http_status <= 599
            else None
        )
        self.stage = stage if isinstance(stage, str) and stage in CLOUD_STAGES else None
        self.application_code = (
            application_code
            if type(application_code) is int and 0 <= application_code <= 65535
            else None
        )
        self.coap_code = (
            coap_code if type(coap_code) is int and 0 <= coap_code <= 255 else None
        )
        super().__init__(code)

    def public(self):
        out = {"status": "failed", "reason": self.code}
        if self.stage is not None:
            out["stage"] = self.stage
        if self.http_status is not None:
            out["http_status"] = self.http_status
        if self.application_code is not None:
            out["application_code"] = self.application_code
        if self.coap_code is not None:
            out["coap_code"] = "%d.%02d" % (self.coap_code >> 5, self.coap_code & 31)
        return out


class Deadline:
    def __init__(self, seconds=240, clock=time.monotonic):
        self.clock = clock
        self.end = clock() + seconds

    def remaining(self, maximum):
        value = min(maximum, self.end - self.clock())
        if value <= 0:
            raise ProbeError("TIME_LIMIT")
        return value


@dataclass(frozen=True, repr=False)
class Identity:
    product: str
    name: str
    firmware: str = field(default="", repr=False)

    def __post_init__(self):
        if (
            self.product != PLUS_KEY
            or not isinstance(self.name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.name)
        ):
            raise ProbeError("TARGET_IDENTITY_REJECTED")

    def public(self):
        return {
            "plus_identity_verified": True,
            "expected_firmware_matches": self.firmware == EXPECTED_FIRMWARE,
        }


@dataclass(frozen=True, repr=False)
class Access:
    identity: Identity
    key: str
    token: str

    def __post_init__(self):
        for value in (self.key, self.token):
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 1024
                or value != value.strip()
            ):
                raise ProbeError("ACCESS_MATERIAL_INVALID")

    def private(self):
        return {
            "product": self.identity.product,
            "name": self.identity.name,
            "key": self.key,
            "token": self.token,
        }

    @classmethod
    def load(cls, data, identity):
        if data.get("product") != identity.product or data.get("name") != identity.name:
            raise ProbeError("VAULT_IDENTITY_MISMATCH")
        return cls(identity, data.get("key"), data.get("token"))


@dataclass(frozen=True, repr=False)
class ServerKey:
    prefix: str
    secret: str

    def __post_init__(self):
        if (
            not isinstance(self.prefix, str)
            or len(self.prefix.encode("utf-8")) != 8
            or not re.fullmatch(r"[A-Za-z0-9@_.-]{8}", self.prefix)
        ):
            raise ProbeError("SERVER_PREFIX_INVALID")
        if (
            not isinstance(self.secret, str)
            or not 1 <= len(self.secret.encode("utf-8")) <= 64
            or any(ord(c) < 32 for c in self.secret)
        ):
            raise ProbeError("SERVER_SECRET_INVALID")

    @classmethod
    def generate(cls, excluded=()):
        for _ in range(8):
            prefix = "".join(secrets.choice(ALPHABET) for _ in range(8))
            if prefix not in excluded:
                return cls(prefix, "".join(secrets.choice(ALPHABET) for _ in range(16)))
        raise ProbeError("KEY_GENERATION_FAILED")

    def access(self, identity):
        key = self.prefix + "10001"
        token = base64.b64encode(
            hmac.digest(self.secret.encode(), key.encode(), "sha1")
        ).decode()
        return Access(identity, key, token)

    def private(self):
        return {"prefix": self.prefix, "secret": self.secret}


def power_value(data):
    if not isinstance(data, dict):
        raise ProbeError("POWER_UNAVAILABLE")
    value = data.get("PowerSwitch")
    if isinstance(value, dict):
        value = value.get("value")
    if type(value) is not int or value not in (0, 1):
        raise ProbeError("POWER_UNAVAILABLE")
    return value


def outcome(call):
    try:
        value = call()
        return {
            "status": "ok",
            **(value if isinstance(value, dict) else {"power": value}),
        }
    except ProbeError as error:
        return error.public()
    except Exception:
        return {"status": "failed", "reason": "INTERNAL_ERROR"}
