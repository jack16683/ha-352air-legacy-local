#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Focused 352 Plus CoAP diagnostics. Python 3.8+, standard library only.

Run on the NAS host: python3 352_plus_probe.py PLUS_IP > plus-coap-result.txt
Only UDP 5683 GET reads are sent. No power writes, pairing, OTA, cloud login,
credentials, or UDP 11530 access. If live power can be read and stdin is a
terminal, an observation window lets the owner use the physical power button
and restore the initial state. Review the sanitized JSON before sharing.
"""

import argparse
import collections
import ipaddress
import json
import math
import platform
import re
import secrets
import select
import socket
import struct
import sys
import time
from urllib.parse import urlsplit

VERSION = "2.0"
PLUS_KEY = "a1TNKV3wr7I"
PORT = 5683
TIMEOUT = 3.0
MAX_BYTES = 32768
MAX_BLOCKS = 128
MAX_PACKETS = 1024
INFO_PATH = "/sys/device/info/get"
ALCS_PATH = "/dev/core/service/dev"
CORE_PATH = "/.well-known/core"
READ_METHOD = "thing.service.property.get"
READ_KEYS = ("PowerSwitch", "WorkMode", "WindSpeed")
# Exact APK property identifiers. No arbitrary numeric/string values are exposed.
STATE_KEYS = set(READ_KEYS) | {
    "ScreenSwitch",
    "ChildLockSwitch",
    "StandbySensorSwitch",
    "SmartModeSwitch",
    "IonsSwitch",
    "PM25",
    "HCHO",
    "TVOC",
    "CO2",
    "WindValue",
    "DeviceType",
    "RelativeHumidity",
    "CurrentTemperature",
    "FilterLifeTimePercent_1",
    "FilterLifeTimePercent_2",
    "FilterLifeTimePercent_3",
    "powerstate",
    "mode",
    "windspeed",
    "OSD",
    "childLockOnOff",
    "LocalTimer",
    "timingShutdownTime",
}
META_INTS = {"service", "cipherType", "type", "tokenType", "remainTime"}
VERSION_KEYS = {
    "smartconfig",
    "zconfig",
    "router",
    "ap",
    "softap",
    "awss",
    "alcs",
    "coap",
    "ota",
    "log",
    "errcode",
    "offlineLog",
    "offlineOta",
    "bind",
}
STATIC_SEGMENTS = {
    "sys",
    "dev",
    "core",
    "service",
    "device",
    "info",
    "get",
    "set",
    "auth",
    "property",
    "thing",
    "model",
    "method",
    "notify",
    "event",
    "post",
    "heartBeat",
    "permission",
    "user",
    "awss",
    ".well-known",
    "profile",
}
KNOWN_KEYS = (
    STATE_KEYS
    | META_INTS
    | VERSION_KEYS
    | {
        "id",
        "code",
        "data",
        "params",
        "items",
        "value",
        "version",
        "method",
        "productKey",
        "prodKey",
        "deviceName",
        "mac",
        "ip",
        "fwVersion",
        "awssVer",
        "serviceVer",
        "deviceModel",
        "profile",
        "devices",
        "name",
        "addr",
        "port",
        "pal",
        "services",
        "properties",
        "events",
        "identifier",
        "accessMode",
        "dataType",
        "specs",
        "min",
        "max",
        "step",
        "unit",
        "message",
        "msg",
        "token",
        "random",
        "accessKey",
        "accessToken",
    }
)
PRIVATE = {
    "id",
    "deviceName",
    "mac",
    "ip",
    "name",
    "addr",
    "token",
    "random",
    "accessKey",
    "accessToken",
    "sessionKey",
    "sessionId",
    "sign",
    "randomKey",
}


def hidden(value):
    result = {"redacted_type": type(value).__name__}
    if isinstance(value, (str, dict, list)):
        result["length"] = len(value)
    return result


def error_info(exc):
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None)}


def scalar(value):
    return (
        type(value) in {int, float}
        and -100000 <= value <= 1000000
        and math.isfinite(value)
    )


def safe_json(value, key="", depth=0, parent=""):
    """Keep known capabilities/state, never arbitrary text or credentials."""
    if key in PRIVATE:
        return hidden(value)
    if depth > 7:
        return "<depth-limit>"
    if isinstance(value, dict):
        out = {}
        for n, (child, item) in enumerate(value.items()):
            if n >= 64:
                out["omitted_fields"] = len(value) - 64
                break
            name = child if child in KNOWN_KEYS else "unknown_field_" + str(n)
            out[name] = safe_json(item, child, depth + 1, key)
        return out
    if isinstance(value, list):
        return [safe_json(v, key, depth + 1, parent) for v in value[:32]] + (
            [{"omitted_items": len(value) - 32}] if len(value) > 32 else []
        )
    if value is None:
        return None
    if key in META_INTS and type(value) is int and 0 <= value <= 2147483647:
        return value
    if (
        key in META_INTS
        and isinstance(value, str)
        and re.fullmatch(r"\d{1,10}", value)
        and int(value) <= 2147483647
    ):
        return value
    if key in {"code", "port"} and type(value) is int and 0 <= value <= 2147483647:
        return value
    if key in STATE_KEYS or (key == "value" and parent in STATE_KEYS):
        if scalar(value) or type(value) is bool:
            return value
        if isinstance(value, str) and re.fullmatch(r"-?\d{1,6}(?:\.\d{1,4})?", value):
            return value
    if key in {"productKey", "prodKey"} and value == PLUS_KEY:
        return value
    if (
        key == "fwVersion"
        and isinstance(value, str)
        and re.fullmatch(
            r"\d{1,2}\.\d{1,2}\.\d{1,2}(?:_[A-Za-z]{1,8}\d{2,5}[A-Za-z]{0,3})?", value
        )
    ):
        return value
    if (
        key in VERSION_KEYS | {"version"}
        and isinstance(value, str)
        and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", value)
    ):
        return value
    if key == "identifier" and value in STATE_KEYS | {"get", "set"}:
        return value
    if key == "method" and value in {
        READ_METHOD,
        "thing.service.property.set",
        "device.info.get",
        "core.service.dev",
    }:
        return value
    if key in {"pal", "accessMode", "dataType"} and value in (
        "linkkit",
        "alink",
        "r",
        "w",
        "rw",
        "int",
        "float",
        "bool",
        "enum",
        "struct",
        "array",
        "string",
    ):
        return value
    if key in {"message", "msg"} and isinstance(value, str):
        # Diagnostic categories only: vendor error strings can echo secrets.
        return {
            "categories": [
                tag
                for tag, words in (
                    ("auth", ("auth", "sign", "permission", "session", "token")),
                    ("request", ("param", "format", "invalid")),
                    ("resource", ("not found", "resource", "method")),
                )
                if any(word in value.lower() for word in words)
            ]
        }
    return hidden(value)


def uint(value):
    return value.to_bytes(max(0, (value.bit_length() + 7) // 8), "big")


def option_part(value):
    if value < 13:
        return value, b""
    if value < 269:
        return 13, bytes((value - 13,))
    if value <= 65804:
        return 14, struct.pack("!H", value - 269)
    raise ValueError("option_too_long")


def encode_get(
    path,
    token,
    mid,
    body=None,
    confirmable=True,
    content_format=50,
    accept=None,
    block=None,
):
    if not path.startswith("/") or len(token) != 8:
        raise ValueError("invalid_request")
    options = [(11, part.encode()) for part in path.strip("/").split("/")]
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    if payload and content_format is not None:
        options.append((12, uint(content_format)))
    if accept is not None:
        options.append((17, uint(accept)))
    if block is not None:
        options.append((23, uint(block)))
    result = bytearray(
        bytes((0x48 if confirmable else 0x58, 1)) + struct.pack("!H", mid) + token
    )
    previous = 0
    for number, value in sorted(options, key=lambda item: item[0]):
        delta, de = option_part(number - previous)
        length, le = option_part(len(value))
        result.extend(bytes(((delta << 4) | length,)) + de + le + value)
        previous = number
    return bytes(result) + (b"\xff" + payload if payload else b"")


def decode(data):
    if len(data) < 4 or data[0] >> 6 != 1 or data[0] & 15 > 8:
        raise ValueError("invalid_header")
    length = data[0] & 15
    if len(data) < 4 + length:
        raise ValueError("truncated_token")
    result = {
        "type": (data[0] >> 4) & 3,
        "code": data[1],
        "mid": int.from_bytes(data[2:4], "big"),
        "token": data[4 : 4 + length],
        "options": {},
    }
    offset, number = 4 + length, 0
    while offset < len(data) and data[offset] != 255:
        h = data[offset]
        offset += 1
        values = []
        for nibble in (h >> 4, h & 15):
            if nibble == 15:
                raise ValueError("reserved_option")
            n = 1 if nibble == 13 else 2 if nibble == 14 else 0
            if offset + n > len(data):
                raise ValueError("truncated_option")
            values.append(
                nibble
                if not n
                else int.from_bytes(data[offset : offset + n], "big")
                + (13 if n == 1 else 269)
            )
            offset += n
        number += values[0]
        if offset + values[1] > len(data):
            raise ValueError("truncated_value")
        if number in result["options"] and number in {4, 12, 23, 28}:
            raise ValueError("duplicate_option")
        if len(result["options"]) >= 64:
            raise ValueError("option_limit")
        result["options"][number] = data[offset : offset + values[1]]
        offset += values[1]
    if offset < len(data) and offset + 1 == len(data):
        raise ValueError("empty_payload_marker")
    result["payload"] = data[offset + 1 :] if offset < len(data) else b""
    return result


class Blocks:
    """Bounded contiguous Block2 assembly, with representation consistency checks."""

    def __init__(self):
        self.parts = bytearray()
        self.count = 0
        self.signature = None
        self.last = None

    def add(self, packet):
        options = packet["options"]
        content_format = options.get(12)
        if content_format is not None:
            if len(content_format) > 2:
                raise ValueError("invalid_content_format")
            content_format = int.from_bytes(content_format, "big")
        sig = (packet["code"], options.get(4), content_format)
        if self.signature is not None:
            old_code, old_etag, old_format = self.signature
            if sig[:2] != (old_code, old_etag):
                raise ValueError("representation_changed")
            if old_format is not None and sig[2] is not None and old_format != sig[2]:
                raise ValueError("representation_changed")
            sig = (sig[0], sig[1], sig[2] if sig[2] is not None else old_format)
        self.signature = sig
        payload = packet["payload"]
        raw = options.get(23)
        if raw is None:
            if self.count:
                raise ValueError("missing_block_option")
            if len(payload) > MAX_BYTES:
                raise ValueError("body_limit")
            self.parts.extend(payload)
            self.count = 1
            return None
        if len(raw) > 3:
            raise ValueError("invalid_block_option")
        value = int.from_bytes(raw, "big")
        size_exp = value & 7
        if size_exp == 7:
            raise ValueError("bert_not_supported_on_udp")
        size = 1 << (size_exp + 4)
        number, more = value >> 4, bool(value & 8)
        if self.last == (value, payload):
            return "duplicate"
        if (
            number * size != len(self.parts)
            or len(payload) > size
            or (more and len(payload) != size)
        ):
            raise ValueError("noncontiguous_block")
        if len(self.parts) + len(payload) > MAX_BYTES or self.count >= MAX_BLOCKS:
            raise ValueError("body_or_block_limit")
        self.parts.extend(payload)
        self.count += 1
        self.last = (value, payload)
        return (((len(self.parts) // size) << 4) | size_exp) if more else None


class Client:
    def __init__(self, target, timeout=TIMEOUT, port=PORT):
        self.peer = (target, port)
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.connect(self.peer)  # Kernel filters other source IP/ports.
            self.sock.setblocking(False)
        except OSError:
            self.sock.close()
            raise
        self.counts = collections.Counter()
        self.deadline = time.monotonic() + 180
        self.serial = secrets.randbits(30)
        self.message_id = secrets.randbits(16)

    def next_mid(self):
        value = self.message_id
        self.message_id = (value + 1) & 65535
        return value

    def close(self):
        self.sock.close()

    def request(
        self,
        name,
        path,
        method=None,
        params=None,
        confirmable=True,
        content_format=50,
        accept=None,
    ):
        self.serial += 1
        request_id = str(self.serial)
        body = (
            None
            if method is None
            else {
                "id": request_id,
                "version": "1.0",
                "method": method,
                "params": params,
            }
        )
        token, mid = secrets.token_bytes(8), self.next_mid()
        mids = {mid}
        packet = encode_get(path, token, mid, body, confirmable, content_format, accept)
        start = time.monotonic()
        end = min(self.deadline, start + self.timeout * 3)
        result = {
            "probe": name,
            "status": "timeout",
            "security": "no_session_diagnostic",
            "sent": 0,
            "empty_acks": 0,
            "responses": [],
            "body_complete": False,
        }
        blocks = Blocks()
        next_send, transmissions, acked = start, 0, False
        parsed = None
        while time.monotonic() < end and self.counts["received"] < MAX_PACKETS:
            now = time.monotonic()
            if transmissions < 2 and not acked and now >= next_send:
                try:
                    self.sock.send(packet)
                except OSError as exc:
                    result.update(status="socket_error", error=error_info(exc))
                    break
                transmissions += 1
                result["sent"] += 1
                next_send = now + self.timeout
            wait = min(0.2, max(0, end - now))
            if transmissions < 2 and not acked:
                wait = min(wait, max(0, next_send - now))
            ready, _, _ = select.select([self.sock], [], [], wait)
            if not ready:
                continue
            try:
                data = self.sock.recv(65535)
            except OSError as exc:
                result.update(status="socket_error", error=error_info(exc))
                break
            self.counts["received"] += 1
            try:
                response = decode(data)
            except ValueError:
                self.counts["malformed"] += 1
                continue
            if (
                response["type"] in {2, 3}
                and response["code"] == 0
                and not response["token"]
            ):
                if response["mid"] != mid:
                    self.counts["unmatched"] += 1
                    continue
                if response["type"] == 3:
                    result["status"] = "reset"
                    break
                result["empty_acks"] += 1
                acked = True
                continue
            if response["token"] != token or response["code"] >> 5 not in {2, 4, 5}:
                self.counts["unmatched"] += 1
                continue
            if response["type"] == 3 or (
                response["type"] == 2 and response["mid"] not in mids
            ):
                self.counts["unmatched"] += 1
                continue
            if response["type"] == 0:
                try:
                    self.sock.send(b"\x60\x00" + struct.pack("!H", response["mid"]))
                except OSError as exc:
                    result["ack_error"] = error_info(exc)
            opt = response["options"]
            summary = {
                "type": ("CON", "NON", "ACK", "RST")[response["type"]],
                "code": f"{response['code'] >> 5}.{response['code'] & 31:02d}",
                "payload_bytes": len(response["payload"]),
                "option_numbers": sorted(opt),
                "elapsed_seconds": round(time.monotonic() - start, 3),
            }
            for number, key in (
                (6, "observe"),
                (12, "content_format"),
                (14, "max_age"),
                (23, "block2"),
                (28, "size2"),
            ):
                if number in opt and len(opt[number]) <= 4:
                    summary[key] = int.from_bytes(opt[number], "big")
            if len(result["responses"]) < MAX_BLOCKS + 4:
                result["responses"].append(summary)
            try:
                next_block = blocks.add(response)
            except ValueError as exc:
                result.update(status="incomplete_representation", reason=str(exc))
                break
            if next_block == "duplicate":
                continue
            if next_block is not None:
                end = min(
                    self.deadline,
                    start + 30,
                    time.monotonic() + self.timeout * 3,
                )
                mid = self.next_mid()
                mids.add(mid)
                packet = encode_get(
                    path,
                    token,
                    mid,
                    body,
                    confirmable,
                    content_format,
                    accept,
                    next_block,
                )
                next_send, transmissions, acked = 0, 0, False
                continue
            result.update(
                status="response",
                body_complete=True,
                blocks=blocks.count,
                body_bytes=len(blocks.parts),
                coap_code=summary["code"],
            )
            payload = bytes(blocks.parts)
            try:
                parsed = json.loads(payload)
                result["format"] = "json"
                result["json"] = safe_json(parsed)
                if isinstance(parsed, dict):
                    result["json_id_present"] = "id" in parsed
                    result["json_id_matches"] = (
                        type(parsed.get("id")) in {int, str}
                        and str(parsed["id"]) == request_id
                    )
                    code = parsed.get("code")
                    result["application_code"] = (
                        code if type(code) is int and 0 <= code <= 2147483647 else None
                    )
            except (ValueError, UnicodeError, RecursionError):
                parsed = None
                if payload and (
                    opt.get(12) == uint(40) or payload.lstrip().startswith(b"<")
                ):
                    result["format"] = "link_format"
                    parsed = payload.decode("utf-8", errors="replace")
                else:
                    result["format"] = "empty" if not payload else "non_json"
                    result["body_description"] = (
                        "omitted; no raw text or binary persisted"
                    )
            break
        if self.counts["received"] >= MAX_PACKETS:
            result["status"] = "packet_budget_exhausted"
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        result["blocks_received"] = blocks.count
        result["assembled_bytes"] = len(blocks.parts)
        return result, parsed


def identity_from(result, body, target):
    if not (
        result.get("coap_code", "").startswith("2.")
        and result.get("json_id_matches")
        and isinstance(body, dict)
        and type(body.get("code")) is int
        and body["code"] == 200
    ):
        return None
    data = body.get("data")
    if not isinstance(data, dict) or data.get("productKey") != PLUS_KEY:
        return None
    name = data.get("deviceName")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        return None
    if data.get("ip") and data["ip"] != target:
        return None
    if data.get("mac") and (
        not isinstance(data["mac"], str)
        or not re.fullmatch(r"(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}", data["mac"])
    ):
        return None
    return PLUS_KEY, name


def properties_from(result, body):
    if not result.get("coap_code", "").startswith("2.") or not isinstance(body, dict):
        return {}
    if result.get("json_id_present") and not result.get("json_id_matches"):
        return {}
    if type(body.get("code")) is not int or body["code"] != 200:
        return {}
    data = body.get("data")
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("items"), dict):
        data = data["items"]
    out = {}
    for key in STATE_KEYS:
        value = data.get(key)
        if isinstance(value, dict):
            value = value.get("value")
        if scalar(value):
            if key == "PowerSwitch" and (type(value) is not int or value not in {0, 1}):
                continue
            out[key] = value
    return out


def read_paths(identity):
    pk, dn = identity
    return {
        f"/sys/{pk}/{dn}/thing/service/property/get",
        f"/dev/{pk}/{dn}/thing/service/property/get",
    }


def core_summary(text, identity, target):
    """Bounded link parsing. Never follow arbitrary links or expose identifiers."""
    links, followed = [], set()
    entries, current, quote, angle, escaped = [], [], False, False, False
    for char in text[:MAX_BYTES]:
        if char == "," and not quote and not angle:
            entries.append("".join(current))
            current = []
            continue
        current.append(char)
        if escaped:
            escaped = False
        elif char == "\\" and quote:
            escaped = True
        elif char == '"':
            quote = not quote
        elif not quote and char == "<":
            angle = True
        elif not quote and char == ">":
            angle = False
    if current:
        entries.append("".join(current))
    for entry in entries[:64]:
        match = re.fullmatch(r"\s*<([^<>]{1,1024})>(.*)\s*", entry, re.S)
        if not match:
            links.append({"parse": "malformed_entry"})
            continue
        try:
            url = urlsplit(match[1])
            local = (not url.scheme and not url.netloc) or (
                url.scheme == "coap"
                and url.hostname == target
                and url.port in {None, PORT}
                and not url.username
                and not url.password
            )
        except ValueError:
            links.append({"parse": "invalid_uri"})
            continue
        path = url.path
        row = {
            "same_target": local,
            "query_present": bool(url.query),
            "path_shape": "/"
            + "/".join(
                "PRODUCT_KEY"
                if identity and part == identity[0]
                else "DEVICE_NAME"
                if identity and part == identity[1]
                else part
                if part in STATIC_SEGMENTS
                else "REDACTED"
                for part in path.strip("/").split("/")
            ),
        }
        attrs = match[2]
        row["observable"] = bool(re.search(r";\s*obs(?:;|\s|$)", attrs))
        cf = re.search(r';\s*ct=(?:"([0-9 ]{1,48})"|(\d{1,5}))', attrs)
        if cf:
            row["content_formats"] = [int(x) for x in (cf[1] or cf[2]).split()[:8]]
        for name in ("rt", "if"):
            attr = re.search(
                r";\s*" + name + r'=(?:"([^"]{0,256})"|([^;\s]{1,256}))', attrs
            )
            if attr:
                value = attr[1] or attr[2]
                row[name] = (
                    value
                    if value
                    in {
                        "core.r",
                        "core.rp",
                        "core.s",
                        "core.a",
                        "core.b",
                        "thing.service.property.get",
                        "core.service.dev",
                    }
                    else "<redacted unrecognized attribute>"
                )
        eligible = (
            identity
            and local
            and not url.query
            and not url.fragment
            and path in read_paths(identity)
        )
        row["allowlisted_property_read"] = bool(eligible)
        if eligible:
            followed.add(path)
        links.append(row)
    return {"entries": links, "omitted_entries": max(0, len(entries) - 64)}, followed


def run(target, observe_seconds=45):
    report = {
        "script_version": VERSION,
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "status": "starting",
        "scope": "Plus UDP5683 reads only; no device writes",
        "target": "TARGET_IP",
        "probes": [],
        "observation": {"status": "not_run"},
        "limitations": [
            "No authorized ALCS session established. Errors from plaintext reads "
            "do not prove lack of local support.",
            "Discovery service bits describe provisioning/maintenance capabilities, "
            "not a control switch.",
            "No UDP11530, DTLS5684, auth, pairing, OTA, resets, cloud requests "
            "or credential guessing.",
        ],
    }
    client = None
    started = time.monotonic()
    successful = []
    try:
        client = Client(target)
        if client.sock.getsockname()[0] == target:
            report["status"] = "target_is_sender"
            return report

        def probe(name, path, method=None, params=None, **kwargs):
            result, body = client.request(name, path, method, params, **kwargs)
            report["probes"].append(result)
            return result, body

        identities = set()
        for con in (False, True):
            result, body = probe(
                "device_info_" + ("con" if con else "non"),
                INFO_PATH,
                "device.info.get",
                {},
                confirmable=con,
            )
            identity = identity_from(result, body, target)
            if identity:
                identities.add(identity)
                report["identity"] = {
                    "product_key": PLUS_KEY,
                    "device_name": "REDACTED",
                    "source_and_request_validated": True,
                }
                service = body["data"].get("service")
                if type(service) is int and 0 <= service <= 65535:
                    report["provisioning_flags"] = {
                        name: bool(service & bit)
                        for bit, name in (
                            (1, "error_code"),
                            (2, "offline_ota"),
                            (4, "offline_log"),
                            (8, "batch_provision"),
                        )
                    }
        identity = next(iter(identities)) if len(identities) == 1 else None
        if len(identities) > 1:
            report["identity_conflict"] = True
        result, body = probe("resource_directory", CORE_PATH, accept=40)
        extra = set()
        if isinstance(body, str) and result.get("coap_code", "").startswith("2."):
            result["resources"], extra = core_summary(body, identity, target)
        # A few devices reject Accept. Record both forms, but only retry on an error.
        if not result.get("coap_code", "").startswith("2."):
            result, body = probe("resource_directory_no_accept", CORE_PATH)
            if isinstance(body, str) and result.get("coap_code", "").startswith("2."):
                result["resources"], extra = core_summary(body, identity, target)
        result, body = probe("alcs_reference", ALCS_PATH, "core.service.dev", {})
        if identity:
            path = "/sys/{}/{}/thing/service/property/get".format(*identity)
            variants = [
                ("named", list(READ_KEYS), True, 50),
                ("empty", [], True, 50),
                ("named_non", list(READ_KEYS), False, 50),
            ]
            for suffix, params, con, content in variants:
                result, body = probe(
                    "property_" + suffix,
                    path,
                    READ_METHOD,
                    params,
                    confirmable=con,
                    content_format=content,
                )
                values = properties_from(result, body)
                if values:
                    result["validated_properties"] = values
                    successful.append((path, params, con, content, values))
            if not successful:
                # A firmware may reject the whole list for one unsupported field.
                result, body = probe(
                    "property_power_only", path, READ_METHOD, ["PowerSwitch"]
                )
                values = properties_from(result, body)
                if values:
                    result["validated_properties"] = values
                    successful.append((path, ["PowerSwitch"], True, 50, values))
            # Content-format fallback is diagnostic, not a claim of authorized SDK use.
            if not successful:
                result, body = probe(
                    "property_named_text_format",
                    path,
                    READ_METHOD,
                    list(READ_KEYS),
                    content_format=0,
                )
                values = properties_from(result, body)
                if values:
                    result["validated_properties"] = values
                    successful.append((path, list(READ_KEYS), True, 0, values))
            for n, advertised in enumerate(sorted(extra - {path})):
                result, body = probe(
                    "advertised_property_read_" + str(n + 1),
                    advertised,
                    READ_METHOD,
                    list(READ_KEYS),
                )
                values = properties_from(result, body)
                if values:
                    result["validated_properties"] = values
                    successful.append((advertised, list(READ_KEYS), True, 50, values))
        else:
            report["property_reads_skipped"] = (
                "conflicting_identity" if identities else "no_correlated_plus_identity"
            )
        baseline = next((r for r in successful if "PowerSwitch" in r[4]), None)
        observation_ready = False
        if (
            baseline
            and observe_seconds
            and sys.stdin.isatty()
            and client.deadline - time.monotonic() >= observe_seconds + 30
        ):
            path, params, con, content, _ = baseline
            result, body = probe(
                "observation_baseline",
                path,
                READ_METHOD,
                params,
                confirmable=con,
                content_format=content,
            )
            fresh = properties_from(result, body)
            baseline = (
                (path, params, con, content, fresh) if "PowerSwitch" in fresh else None
            )
            observation_ready = baseline is not None
        if (
            observation_ready
            and observe_seconds
            and sys.stdin.isatty()
            and client.deadline - time.monotonic() >= observe_seconds
        ):
            path, params, con, content, values = baseline
            initial = values["PowerSwitch"]
            print(
                f"Local power is readable. Within {observe_seconds} seconds, "
                "use the PHYSICAL power button once, hold for 5 seconds, "
                "then RESTORE its original "
                f"{'ON' if initial else 'OFF'} state. "
                "This script sends no power writes.",
                file=sys.stderr,
                flush=True,
            )
            observation = {
                "status": "observing",
                "initial_power": initial,
                "samples": [],
                "change_seen": False,
                "return_seen_after_change": False,
            }
            report["observation"] = observation
            until = min(client.deadline, time.monotonic() + observe_seconds)
            for number in range(20):
                if time.monotonic() >= until:
                    break
                result, body = probe(
                    "state_observation_" + str(number + 1),
                    path,
                    READ_METHOD,
                    params,
                    confirmable=con,
                    content_format=content,
                )
                current = properties_from(result, body)
                if "PowerSwitch" in current:
                    power = current["PowerSwitch"]
                    observation["samples"].append(
                        {
                            "seconds": round(time.monotonic() - started, 2),
                            "properties": current,
                        }
                    )
                    if power != initial:
                        observation["change_seen"] = True
                    elif observation["change_seen"]:
                        observation["return_seen_after_change"] = True
                        break
                time.sleep(min(2, max(0, until - time.monotonic())))
            observation["status"] = (
                "change_and_return_observed"
                if observation["return_seen_after_change"]
                else "change_seen_restore_not_confirmed"
                if observation["change_seen"]
                else "no_change_observed"
            )
            if (
                observation["change_seen"]
                and not observation["return_seen_after_change"]
            ):
                print(
                    "Original power restoration was NOT observed. "
                    "Check and restore the device manually.",
                    file=sys.stderr,
                )
        else:
            report["observation"]["status"] = (
                "skipped_no_power_read"
                if not baseline
                else "skipped_noninteractive_disabled_or_time_budget"
            )
        report["status"] = "complete"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        if report["observation"].get("status") == "observing":
            report["observation"]["status"] = "interrupted_check_original_power"
            print(
                "Interrupted: check and restore original power manually.",
                file=sys.stderr,
            )
    except (OSError, ValueError) as exc:
        report.update(status="runtime_error", error=error_info(exc))
    finally:
        if client:
            report["receive_counts"] = dict(client.counts)
            client.close()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    codes = {r.get("coap_code") for r in report["probes"] if "property" in r["probe"]}
    if successful:
        report["next_step"] = (
            "Local properties returned. Verify observed state changes; "
            "device writes remain untested."
        )
    elif codes & {"4.01", "4.03"}:
        report["next_step"] = (
            "Property request received authorization/permission error. "
            "Investigate a legitimate secure session."
        )
    else:
        report["next_step"] = (
            "Review capability and resource/error evidence. "
            "No usable plaintext property read established; "
            "this is not proof local control is absent."
        )
    return report


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Plus IPv4; never printed")
    parser.add_argument(
        "--observe-seconds",
        type=int,
        default=45,
        help="Physical-button observation window, 0-60 seconds",
    )
    parser.add_argument(
        "--check-runtime",
        action="store_true",
        help="Offline self-check without any network access",
    )
    args = parser.parse_args()
    if sys.version_info < (3, 8):  # noqa: UP036 -- Standalone NAS baseline.
        parser.error("Python 3.8+ required")
    if args.check_runtime:
        packet = encode_get(CORE_PATH, b"12345678", 42, accept=40)
        assert decode(packet)["code"] == 1
        print(
            json.dumps(
                {
                    "status": "runtime_ok",
                    "script_version": VERSION,
                    "python": platform.python_version(),
                }
            )
        )
        return 0
    try:
        address = ipaddress.IPv4Address(args.target or "")
        if (
            address.is_multicast
            or address.is_unspecified
            or str(address) == "255.255.255.255"
        ):
            raise ValueError
    except ValueError:
        parser.error("Supply a valid Plus host IPv4")
    if not 0 <= args.observe_seconds <= 60:
        parser.error("Observation window must be 0-60 seconds")
    print(
        "Starting Plus CoAP READ-ONLY diagnostics. No power writes. "
        "Typical scan under 90s; watch stderr for an optional "
        "physical-button observation window.",
        file=sys.stderr,
        flush=True,
    )
    report = run(str(address), args.observe_seconds)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    observation = report["observation"]
    if observation.get("change_seen") and not observation.get(
        "return_seen_after_change"
    ):
        return 2
    if report["status"] == "interrupted":
        return 130
    return 1 if report["status"] in {"runtime_error", "target_is_sender"} else 0


if __name__ == "__main__":
    sys.exit(main())
