"""Bounded UDP transport. Only one logical setup and exactly one write datagram."""

from __future__ import annotations

import ipaddress
import secrets
import select
import socket
import time

from . import primitives as wire
from .model import ALPHABET, PLUS_KEY, Deadline, Identity, ProbeError
from .protocol import Session, auth_body, object_json


class LanClient:
    def __init__(
        self, host, *, port=5683, deadline=None, timeout=2.0, allow_loopback=False
    ):
        try:
            address = ipaddress.IPv4Address(host)
        except Exception:
            raise ProbeError("TARGET_ADDRESS_INVALID") from None
        networks = (
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        )
        if not any(address in n for n in networks) and not (
            allow_loopback and address.is_loopback
        ):
            raise ProbeError("TARGET_ADDRESS_INVALID")
        self.host = str(address)
        self.deadline = deadline or Deadline()
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((self.host, port))
        self.sock.setblocking(False)
        self.identity = None
        self.session = None
        self.write_used = False
        self.stats = {
            "datagrams_sent": 0,
            "datagrams_received": 0,
            "discarded": 0,
            "empty_acks": 0,
            "acks_sent": 0,
            "write_datagrams": 0,
        }

    def close(self):
        self.sock.close()

    def _exchange(self, path, body, options=(), *, write=False):
        if write:
            if self.write_used:
                raise ProbeError("WRITE_ALREADY_ATTEMPTED")
            self.write_used = True
        # Explicit method/path allowlist; caller cannot turn the reader into a setter.
        if self.identity:
            allowed = {
                f"/dev/{self.identity.product}/{self.identity.name}/core/service/auth",
                f"/sys/{self.identity.product}/{self.identity.name}/thing/service/property/get",
            }
            setup = (
                f"/dev/{self.identity.product}/{self.identity.name}/core/service/setup"
            )
        else:
            allowed = set()
            setup = ""
        if path != "/sys/device/info/get" and not (
            (not write and path in allowed) or (write and path == setup)
        ):
            raise ProbeError("PATH_NOT_ALLOWED")
        mid, token = secrets.randbelow(65536), secrets.token_bytes(8)
        packet = bytearray(wire.encode(mid, token, path, body, list(options)))
        packet[1] = 3 if write else 1
        deadline = time.monotonic() + self.deadline.remaining(self.timeout * 3)
        next_send = time.monotonic()
        sent = 0
        acked = False
        maximum = 1 if write else 2
        received = 0
        while time.monotonic() < deadline and received < 64:
            now = time.monotonic()
            if sent < maximum and not acked and now >= next_send:
                try:
                    self.sock.send(packet)
                except OSError:
                    raise ProbeError("SEND_FAILED") from None
                sent += 1
                self.stats["datagrams_sent"] += 1
                if write:
                    self.stats["write_datagrams"] += 1
                next_send = now + self.timeout
            wait = min(0.1, max(0, deadline - now))
            if sent < maximum and not acked:
                wait = min(wait, max(0, next_send - now))
            ready, _, _ = select.select([self.sock], [], [], wait)
            if not ready:
                continue
            try:
                data = self.sock.recv(16385)
            except OSError:
                raise ProbeError("RECEIVE_FAILED") from None
            received += 1
            self.stats["datagrams_received"] += 1
            try:
                kind, code, response_mid, actual, opts, payload = wire.decode(data)
            except Exception:
                self.stats["discarded"] += 1
                continue
            if kind in (2, 3) and code == 0 and not actual and response_mid == mid:
                if kind == 3:
                    raise ProbeError("COAP_RESET")
                acked = True
                self.stats["empty_acks"] += 1
                continue
            if (
                actual != token
                or kind not in (0, 1, 2)
                or code >> 5 not in (2, 4, 5)
                or (kind == 2 and response_mid != mid)
            ):
                self.stats["discarded"] += 1
                continue
            if kind == 0:
                self.sock.send(b"\x60\x00" + response_mid.to_bytes(2, "big"))
                self.stats["acks_sent"] += 1
            if code != 69:
                raise ProbeError("COAP_ERROR", coap_code=code)
            if any(n & 1 and n not in (11, 23, 71) for n in opts):
                raise ProbeError("CRITICAL_OPTION_UNSUPPORTED")
            if 23 in opts:
                raise ProbeError("BLOCK2_UNSUPPORTED")
            formats = opts.get(12, [])
            encrypted = any(n == 71 for n, _ in options)
            if len(formats) > 1 or (
                formats
                and (
                    len(formats[0]) > 2
                    or int.from_bytes(formats[0], "big")
                    not in ({42} if encrypted else {0, 50})
                )
            ):
                raise ProbeError("CONTENT_FORMAT_UNSUPPORTED")
            return opts, payload
        raise ProbeError("WRITE_OUTCOME_UNKNOWN" if write else "TIMEOUT")

    def identify(self):
        request_id = secrets.randbelow(2**31)
        opts, payload = self._exchange(
            "/sys/device/info/get",
            wire._json("device.info.get", {}, request_id),
            [(12, b"\x32")],
        )
        obj = object_json(payload)
        if str(obj.get("id")) != str(request_id):
            raise ProbeError("JSON_ID_MISMATCH")
        data = obj.get("data")
        if (
            type(obj.get("code")) is not int
            or obj["code"] != 200
            or not isinstance(data, dict)
        ):
            raise ProbeError("IDENTITY_INVALID")
        if data.get("ip") is not None and data["ip"] != self.host:
            raise ProbeError("IDENTITY_ADDRESS_MISMATCH")
        if data.get("productKey") != PLUS_KEY:
            raise ProbeError("TARGET_IDENTITY_REJECTED")
        self.identity = Identity(
            PLUS_KEY, data.get("deviceName"), data.get("fwVersion", "")
        )
        return self.identity

    def authenticate(self, access):
        if (
            self.identity is None
            or access.identity.product != self.identity.product
            or access.identity.name != self.identity.name
        ):
            raise ProbeError("TARGET_IDENTITY_REJECTED")
        nonce = "".join(secrets.choice(ALPHABET) for _ in range(15))
        request_id = secrets.randbelow(2**31)
        path = f"/dev/{self.identity.product}/{self.identity.name}/core/service/auth"
        opts, payload = self._exchange(path, auth_body(access, nonce, request_id))
        self.session = Session.authenticate(payload, access, nonce, request_id)
        return {"status": "ok", "server_proof_verified": True, "opt": self.session.opt}

    def read_power(self):
        if self.session is None:
            raise ProbeError("AUTH_REQUIRED")
        request_id = secrets.randbelow(2**31)
        body, options = self.session.read_payload(request_id)
        path = f"/sys/{self.identity.product}/{self.identity.name}/thing/service/property/get"
        opts, payload = self._exchange(path, body, options)
        return self.session.read_reply(payload, opts, request_id)

    def install(self, server_key, before_send):
        if self.session is None:
            raise ProbeError("AUTH_REQUIRED")
        if self.write_used:
            raise ProbeError("WRITE_ALREADY_ATTEMPTED")
        request_id = secrets.randbelow(2**31)
        body, options = self.session.setup_payload(server_key, request_id)
        path = f"/dev/{self.identity.product}/{self.identity.name}/core/service/setup"
        # Durable journal first. If it fails, no write may leave the socket.
        before_send()
        opts, payload = self._exchange(path, body, options, write=True)
        self.session.reply(payload, opts, request_id)
        return {"status": "acknowledged", "new_key_effectiveness": "not_yet_verified"}
