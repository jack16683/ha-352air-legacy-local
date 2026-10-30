# SPDX-License-Identifier: GPL-3.0-or-later
"""ALCS primitives previously checked against the APK native oracle."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_IV = b"a1b1c1d1e1f1g1h1"


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
