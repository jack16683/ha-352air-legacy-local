# SPDX-License-Identifier: GPL-3.0-or-later
"""Experimental ALCS power client; model and firmware compatibility unverified.

Wire details cross-checked with aliyun/iotkit-embedded ALCS (Apache-2.0),
https://github.com/aliyun/iotkit-embedded/tree/0d3beeedb31a39f4b54fb4c521e8ce63f23e817c/src/dev_model/alcs
and the 352Life APK. No discovery tokens are used as credentials.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PLUS_KEY = "a1TNKV3wr7I"
_IV = b"a1b1c1d1e1f1g1h1"
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class AlcsError(Exception):
    """Generic, non-sensitive failure; no packet or credentials are logged."""


class AlcsOutcomeUnknown(AlcsError):
    """A write was attempted but its result could not be confirmed."""


@dataclass(frozen=True, slots=True)
class Credentials:
    product_key: str
    device_name: str = field(repr=False)
    access_key: str = field(repr=False)
    access_token: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.product_key != PLUS_KEY:
            raise ValueError("Experimental control only supports X83C Plus")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.device_name):
            raise ValueError("Invalid device identity")
        for value in (self.access_key, self.access_token):
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 1024
                or value != value.strip()
            ):
                raise ValueError("Invalid credentials")


def _crypt(data: bytes, key: bytes, encrypt: bool) -> bytes:
    ctx = Cipher(algorithms.AES(key[:16]), modes.CBC(_IV))
    transform = ctx.encryptor() if encrypt else ctx.decryptor()
    return transform.update(data) + transform.finalize()


def encrypt(payload: bytes, key: bytes) -> bytes:
    if not payload or len(key) < 16:
        raise ValueError("Invalid ALCS data")
    count = len(payload) & ~15
    padding = 16 - (len(payload) - count)
    return _crypt(payload[:count], key, True) + _crypt(
        payload[count:] + bytes([padding]) * padding, key, True
    )


def decrypt(payload: bytes, key: bytes) -> bytes:
    if not payload or len(payload) % 16 or len(key) < 16:
        raise ValueError("Invalid ALCS ciphertext")
    last = _crypt(payload[-16:], key, False)
    padding = last[-1]
    if not 1 <= padding <= 16 or last[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid ALCS padding")
    return _crypt(payload[:-16], key, False) + last[:-padding]


def _extended(value: int) -> tuple[int, bytes]:
    if value < 0:
        raise ValueError("Invalid option")
    if value < 13:
        return value, b""
    if value < 269:
        return 13, bytes([value - 13])
    if value <= 65804:
        return 14, (value - 269).to_bytes(2, "big")
    raise ValueError("Option too large")


def encode(
    mid: int, token: bytes, path: str, body: bytes, options: list[tuple[int, bytes]]
) -> bytes:
    if not 0 <= mid <= 65535 or len(token) != 8 or not path.startswith("/"):
        raise ValueError("Invalid CoAP request")
    parts = [(11, part.encode()) for part in path.split("/") if part]
    parts.extend(options)
    parts.sort(key=lambda part: part[0])
    out = bytearray(b"\x48\x01" + mid.to_bytes(2, "big") + token)
    prev = 0
    for number, value in parts:
        delta, de = _extended(number - prev)
        length, le = _extended(len(value))
        out.extend(bytes([delta << 4 | length]) + de + le + value)
        prev = number
    return bytes(out) + (b"\xff" + body if body else b"")


def _option_value(n: int, data: bytes, pos: int) -> tuple[int, int]:
    if n < 13:
        return n, pos
    size = {13: 1, 14: 2}.get(n)
    if size is None or pos + size > len(data):
        raise ValueError("Invalid CoAP option")
    return int.from_bytes(data[pos : pos + size], "big") + (
        13 if size == 1 else 269
    ), pos + size


def decode(data: bytes) -> tuple[int, int, int, bytes, dict[int, list[bytes]], bytes]:
    if len(data) < 4 or len(data) > 16384 or data[0] >> 6 != 1:
        raise ValueError("Invalid CoAP packet")
    length = data[0] & 15
    if length > 8 or len(data) < 4 + length:
        raise ValueError("Invalid CoAP token")
    kind, code, mid = (data[0] >> 4) & 3, data[1], int.from_bytes(data[2:4], "big")
    token, pos, number = data[4 : 4 + length], 4 + length, 0
    opts: dict[int, list[bytes]] = {}
    while pos < len(data) and data[pos] != 255:
        header = data[pos]
        pos += 1
        delta, pos = _option_value(header >> 4, data, pos)
        size, pos = _option_value(header & 15, data, pos)
        number += delta
        if pos + size > len(data):
            raise ValueError("Invalid CoAP option length")
        opts.setdefault(number, []).append(data[pos : pos + size])
        pos += size
    if pos < len(data) and pos + 1 == len(data):
        raise ValueError("Empty CoAP payload")
    return kind, code, mid, token, opts, data[pos + 1 :] if pos < len(data) else b""


def _object(raw: bytes) -> dict:
    def pairs(items: list[tuple[str, object]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    obj = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(obj, dict):
        raise ValueError("Invalid response")
    return obj


def _json(method: str, params: object, mid: int) -> bytes:
    return json.dumps(
        {"id": str(mid), "version": "1.0", "method": method, "params": params},
        separators=(",", ":"),
    ).encode()


class ExperimentalPowerClient:
    """One-shot authenticated transactions, bounded and never retried on writes."""

    def __init__(self, host: str, credentials: Credentials, timeout: float = 5) -> None:
        address = ipaddress.IPv4Address(host)
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or int(address) == 0xFFFFFFFF
        ):
            raise ValueError("Invalid device address")
        self._host = str(address)
        self._credentials = credentials
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._port = 5683

    async def update_host(self, host: str) -> None:
        """Change the address only between transactions, after identity discovery."""
        address = ipaddress.IPv4Address(host)
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError("Invalid device address")
        async with self._lock:
            self._host = str(address)

    async def _exchange(
        self, sock: socket.socket, path: str, body: bytes, sid: int | None = None
    ) -> dict:
        loop = asyncio.get_running_loop()
        mid, token = secrets.randbelow(65536), secrets.token_bytes(8)
        options = [(12, b"\x32" if sid is None else b"\x2a")]
        if sid is not None:
            options.append((71, sid.to_bytes(4, "big")))
        await loop.sock_sendto(
            sock, encode(mid, token, path, body, options), (self._host, self._port)
        )
        deadline = loop.time() + self._timeout
        while True:
            async with asyncio.timeout(max(0, deadline - loop.time())):
                data, source = await loop.sock_recvfrom(sock, 16385)
            if source != (self._host, self._port):
                continue
            try:
                kind, code, response_mid, actual_token, opts, payload = decode(data)
                if kind == 2 and code == 0 and response_mid == mid and not actual_token:
                    continue
                if actual_token != token or code != 69 or kind not in {0, 1, 2}:
                    continue
                if kind == 2 and response_mid != mid:
                    continue
                if sid is not None and (
                    len(opts.get(71, [])) != 1
                    or not 1 <= len(opts[71][0]) <= 4
                    or int.from_bytes(opts[71][0], "big") != sid
                ):
                    continue
                formats = opts.get(12, [])
                if len(formats) > 1 or (
                    formats
                    and (
                        len(formats[0]) > 2
                        or int.from_bytes(formats[0], "big")
                        not in ({0, 50} if sid is None else {42})
                    )
                ):
                    continue
                if 23 in opts or any(n & 1 and n not in {11, 71} for n in opts):
                    continue
                if kind == 0:
                    await loop.sock_sendto(
                        sock, b"\x60\x00" + response_mid.to_bytes(2, "big"), source
                    )
                return {"payload": payload, "mid": mid}
            except ValueError:
                continue

    async def _auth(self, sock: socket.socket) -> tuple[int, bytes]:
        creds = self._credentials
        nonce = "".join(secrets.choice(_ALPHABET) for _ in range(15))
        sign = base64.b64encode(
            hmac.new(creds.access_token.encode(), nonce.encode(), hashlib.sha1).digest()
        ).decode()
        req_id = secrets.randbelow(2**31)
        body = json.dumps(
            {
                "version": "1.0",
                "method": "core/service/auth",
                "id": req_id,
                "params": {
                    "prodKey": creds.product_key,
                    "deviceName": creds.device_name,
                    "encrypt": "payload",
                    "randomKey": nonce,
                    "sign": sign,
                    "accessKey": creds.access_key,
                },
            },
            separators=(",", ":"),
        ).encode()
        response = await self._exchange(
            sock,
            f"/dev/{creds.product_key}/{creds.device_name}/core/service/auth",
            body,
        )
        obj = _object(response["payload"])
        if (
            str(obj.get("id")) != str(req_id)
            or obj.get("code") != 200
            or not isinstance(obj.get("data"), dict)
        ):
            raise AlcsError("Authentication rejected")
        data = obj["data"]
        server, proof, sid = (
            data.get("randomKey"),
            data.get("sign"),
            data.get("sessionId"),
        )
        if (
            not isinstance(server, str)
            or not re.fullmatch(r"[A-Za-z0-9]{15}", server)
            or not isinstance(proof, str)
        ):
            raise AlcsError("Unsupported authentication response")
        expected = base64.b64encode(
            hmac.new(
                creds.access_token.encode(), server.encode() + b"\x00", hashlib.sha1
            ).digest()
        ).decode()
        if not hmac.compare_digest(proof, expected):
            raise AlcsError("Authentication proof failed")
        opt = data.get("opt", 0)
        if type(opt) is not int or opt not in {0, 1}:
            raise AlcsError("Unsupported session options")
        if (
            type(sid) not in {int, str}
            or not str(sid).isdigit()
            or not 1 <= int(sid) <= 0xFFFFFFFF
        ):
            raise AlcsError("Invalid session")
        key = hmac.new(
            creds.access_token.encode(), (nonce + server).encode(), hashlib.sha1
        ).digest()
        return int(sid), key

    async def _property(
        self,
        sock: socket.socket,
        sid: int,
        key: bytes,
        write: bool,
        value: bool | None = None,
    ) -> dict:
        method = "thing.service.property.set" if write else "thing.service.property.get"
        params = {"PowerSwitch": int(value)} if write else ["PowerSwitch"]
        req_id = secrets.randbelow(2**31)
        path = (
            f"/sys/{self._credentials.product_key}/{self._credentials.device_name}/"
            f"{method.replace('.', '/')}"
        )
        response = await self._exchange(
            sock, path, encrypt(_json(method, params, req_id), key), sid
        )
        obj = _object(decrypt(response["payload"], key))
        if (
            str(obj.get("id")) != str(req_id)
            or obj.get("code") != 200
            or not isinstance(obj.get("data"), dict)
        ):
            raise AlcsError("Property request rejected")
        return obj["data"]

    @staticmethod
    def _power(data: dict) -> bool:
        value = data.get("PowerSwitch")
        if isinstance(value, dict):
            value = value.get("value")
        if type(value) is not int or value not in {0, 1}:
            raise AlcsError("Power state is unavailable")
        return bool(value)

    async def read(self) -> bool:
        async with self._lock:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    sid, key = await self._auth(sock)
                    return self._power(await self._property(sock, sid, key, False))
            except (OSError, TimeoutError, ValueError, UnicodeError) as exc:
                raise AlcsError("Local authentication or read failed") from exc

    async def set_power(self, desired: bool) -> bool:
        if type(desired) is not bool:
            raise ValueError("Power must be boolean")
        async with self._lock:
            attempted = False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.setblocking(False)
                    sid, key = await self._auth(sock)
                    current = self._power(await self._property(sock, sid, key, False))
                    if current == desired:
                        return current
                    attempted = True
                    await self._property(sock, sid, key, True, desired)
                    # A fresh read, not an ACK or a guessed local value, is required.
                    actual = self._power(await self._property(sock, sid, key, False))
                    if actual != desired:
                        raise AlcsError("Power state did not confirm")
                    return actual
            except asyncio.CancelledError:
                raise
            except (OSError, TimeoutError, ValueError, UnicodeError, AlcsError) as exc:
                if attempted:
                    raise AlcsOutcomeUnknown(
                        "Power write outcome is unconfirmed"
                    ) from exc
                raise AlcsError("Local authentication or read failed") from exc
