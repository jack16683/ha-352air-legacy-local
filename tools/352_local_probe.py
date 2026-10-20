#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Standalone 352 LAN diagnostics. Python 3.8+, standard library only.

Run on the NAS host, not inside the OpenClaw container:
  sh 352_local_probe.sh PLUS_IP [X83C_IP] > probe-result.txt
Or directly with Python 3.8+:
  python3 352_local_probe.py PLUS_IP [X83C_IP] > probe-result.txt
Optional: --mac AA:BB:CC:DD:EE:FF --bind NAS_IP --broadcast SUBNET_BROADCAST

The launcher checks host Python, then an existing HA container in host mode.
Optional tcpdump, if already available/permitted, records UDP header counters
only. No raw packets, packet files, or output from tcpdump are saved.
After discovery, a verified legacy type-2 device is power-tested automatically:
read its state, switch to the opposite state, then restore the original state.
Each change requires a fresh state reply. A failed restore is reported clearly.
CoAP-only devices without implemented/authorized control are skipped.
No binding, Wi-Fi configuration, firmware commands, or cloud requests.
Share only the JSON report. Addresses/identifiers/credentials are redacted;
public product keys and ordinary firmware version strings may remain.
"""

import argparse
import collections
import ipaddress
import json
import os
import platform
import re
import secrets
import select
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

VERSION = "1.2"
LEGACY_PORT = 11530
POWER_TIMEOUT = 4.0
MAX_DETAILS = 96
MAX_PACKETS = 2048
PATHS = {
    "info": ("/sys/device/info/get", "device.info.get"),
    "alcs": ("/dev/core/service/dev", "core.service.dev"),
}
KNOWN_KEYS = {
    "id",
    "code",
    "data",
    "version",
    "deviceModel",
    "profile",
    "devices",
    "prodKey",
    "productKey",
    "deviceName",
    "name",
    "ip",
    "addr",
    "mac",
    "port",
    "fwVersion",
    "productName",
    "model",
    "pal",
    "services",
    "properties",
    "events",
    "service",
    "type",
    "token",
    "random",
    "cipherType",
    "method",
    "params",
    "accessKey",
    "accessToken",
    "message",
    "msg",
}
PRIVATE_KEYS = {
    "id",
    "deviceName",
    "name",
    "ip",
    "addr",
    "mac",
    "token",
    "random",
    "accessKey",
    "accessToken",
    "service",
    "message",
    "msg",
}


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_multicast or address.is_unspecified:
            raise ValueError
        return str(address)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Expected an IPv4 host/broadcast address"
        ) from None


def mac_bytes(value):
    compact = value.replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise argparse.ArgumentTypeError("Expected a six-byte MAC address")
    return bytes.fromhex(compact)


def error_info(exc):
    """Exception strings can contain private addresses or paths."""
    return {"type": type(exc).__name__, "errno": getattr(exc, "errno", None)}


def redacted(value):
    if isinstance(value, (str, list, dict)):
        return f"<redacted {type(value).__name__} length={len(value)}>"
    return f"<redacted {type(value).__name__}>"


def safe_payload(value, key="", depth=0):
    """Allowlist diagnostic structure; never dump arbitrary response text."""
    if key in PRIVATE_KEYS:
        return redacted(value)
    if depth > 5:
        return "<depth-limit>"
    if isinstance(value, dict):
        result = {}
        for number, (child_key, child) in enumerate(value.items()):
            if number == 32:
                result["_omitted_fields"] = len(value) - 32
                break
            output_key = (
                child_key if child_key in KNOWN_KEYS else f"other_field_{number}"
            )
            result[output_key] = safe_payload(child, child_key, depth + 1)
        return result
    if isinstance(value, list):
        result = [safe_payload(item, depth=depth + 1) for item in value[:3]]
        if len(value) > 3:
            result.append(f"<{len(value) - 3} more items>")
        return result
    if (
        key in {"productKey", "prodKey"}
        and isinstance(value, str)
        and re.fullmatch(r"a1[A-Za-z0-9]{9}", value)
    ):
        return value
    if (
        key == "fwVersion"
        and isinstance(value, str)
        and re.fullmatch(
            r"\d{1,2}\.\d{1,2}\.\d{1,2}(?:_[A-Za-z]{1,8}\d{2,5}[A-Za-z]{0,3})?", value
        )
    ):
        return value
    if key in {"code", "port"} and type(value) is int and 0 <= value <= 65535:
        return value
    if key == "version" and value == "1.0":
        return value
    if (
        key == "method"
        and isinstance(value, str)
        and value in {item[1] for item in PATHS.values()}
    ):
        return value
    if key == "pal" and value in ("linkkit", "alink"):
        return value
    if value is None:
        return None
    return redacted(value)


def coap_request(kind, token, mid, request_id, confirmable=False):
    path, method = PATHS[kind]
    payload = json.dumps(
        {"id": request_id, "version": "1.0", "method": method, "params": {}},
        separators=(",", ":"),
    ).encode()
    result = bytearray(
        bytes((0x48 if confirmable else 0x58, 1)) + struct.pack("!H", mid) + token
    )
    previous = 0
    for part in path.strip("/").split("/"):
        data = part.encode("ascii")
        result.append(((11 - previous) << 4) | len(data))
        result.extend(data)
        previous = 11
    return bytes(result) + b"\x11\x32\xff" + payload


def read_coap(data, requests):
    """Diagnostics accept error replies and unusual token lengths for inspection."""
    if len(data) < 4 or data[0] >> 6 != 1:
        return {"format": "unknown"}, None
    length = data[0] & 15
    if length > 8 or len(data) < 4 + length:
        return {"format": "coap", "parse": "invalid_token_length"}, None
    token = data[4 : 4 + length]
    request = requests.get(token)
    mid = int.from_bytes(data[2:4], "big")
    mid_request = next(
        (item for item in requests.values() if item.get("mid") == mid), None
    )
    detail = {
        "format": "coap",
        "type": ("CON", "NON", "ACK", "RST")[(data[0] >> 4) & 3],
        "code": f"{data[1] >> 5}.{data[1] & 31:02d}",
        "token_bytes": length,
        "token_matches_request": request is not None,
        "probe": request["name"] if request else "unmatched",
        "message_id_matches_request": mid_request is not None,
    }
    if not request and data[1] == 0 and detail["type"] in {"ACK", "RST"}:
        detail["probe"] = mid_request["name"] if mid_request else "unmatched"
    offset, option, numbers = 4 + length, 0, []
    try:
        while offset < len(data) and data[offset] != 255:
            header = data[offset]
            offset += 1
            values = []
            for nibble in (header >> 4, header & 15):
                if nibble == 15:
                    raise ValueError
                count = 1 if nibble == 13 else 2 if nibble == 14 else 0
                if offset + count > len(data):
                    raise ValueError
                values.append(
                    int.from_bytes(data[offset : offset + count], "big")
                    + (13 if count == 1 else 269)
                    if count
                    else nibble
                )
                offset += count
            option += values[0]
            if offset + values[1] > len(data):
                raise ValueError
            if len(numbers) < 24:
                numbers.append(option)
            if option in {12, 23} and values[1] <= 3:
                detail["content_format" if option == 12 else "block2"] = int.from_bytes(
                    data[offset : offset + values[1]], "big"
                )
            offset += values[1]
        detail["option_numbers"] = numbers
        payload = data[offset + 1 :] if offset < len(data) else b""
        detail["payload_bytes"] = len(payload)
        if not payload:
            detail["parse"] = "empty_payload"
        elif len(payload) > 16384:
            detail["parse"] = "payload_too_large"
        else:
            body = json.loads(payload)
            detail["parse"] = "json"
            detail["json"] = safe_payload(body)
            detail["json_id_matches_request"] = (
                isinstance(body, dict)
                and type(body.get("id")) in {str, int}
                and request is not None
                and str(body["id"]) == request["id"]
            )
            detail["correlated_success_response"] = (
                request is not None
                and data[1] >> 5 == 2
                and isinstance(body, dict)
                and type(body.get("code")) is int
                and body["code"] == 200
                and detail["json_id_matches_request"]
                and isinstance(body.get("data"), dict)
            )
    except (ValueError, UnicodeError, RecursionError) as exc:
        detail["parse"] = "malformed_options_or_json"
        detail["parse_error"] = type(exc).__name__
        detail["error_offset"] = getattr(exc, "pos", None)
    # Only acknowledge a correlated CON response; never reply to unsolicited requests.
    ack = (
        b"\x60\x00" + data[2:4]
        if (
            request is not None
            and detail["type"] == "CON"
            and data[1] >> 5 in {2, 4, 5}
        )
        else None
    )
    return detail, ack


def read_legacy(data, sequences, target, expected_mac):
    if len(data) < 16 or data[0] != 0xA1:
        return {"format": "unknown"}
    payload = data[16:]
    result = {
        "format": "legacy_a1",
        "operation": f"0x{data[1]:02x}",
        "wire_type": data[13],
        "payload_bytes": len(payload),
        "outer_length_valid": data[8] >= 7
        and len(data) == data[8] + 9
        and data[9] == 0,
        "sequence_matches_request": int.from_bytes(data[10:12], "big") in sequences,
        "mac_matches_input": None
        if expected_mac is None
        else data[2:8] == expected_mac,
        "auth": "<redacted>",
    }
    if payload[:1] == b"\x23" and len(payload) >= 11:
        result["payload_kind"] = (
            "discovery_reply" if data[1] == 6 else "discovery_other"
        )
        result["embedded_mac_matches_header"] = payload[5:11] == data[2:8]
        result["advertised_ip_matches_target"] = payload[1:5] in {
            ipaddress.IPv4Address(target).packed,
            bytes(4),
        }
    elif payload[:3] == b"\x02\x5a\xa1":
        result["payload_kind"] = "a5a0_state_candidate"
        result["state_length_known"] = len(payload) in {33, 65}
    else:
        result["payload_kind"] = "other"
    return result


def legacy_identity(data, peer, target, expected_mac, sequences):
    """Learn control identity only from a coherent target discovery/state frame."""
    if peer != (target, LEGACY_PORT):
        return None
    info = read_legacy(data, sequences, target, expected_mac)
    if (
        info.get("format") != "legacy_a1"
        or not info["outer_length_valid"]
        or info["wire_type"] != 2
        or info["mac_matches_input"] is False
        or data[2:8] in {bytes(6), b"\xff" * 6}
        or data[2] & 1
    ):
        return None
    identity = (data[2:8], data[12], data[14:16])
    if (
        info.get("payload_kind") == "discovery_reply"
        and info["sequence_matches_request"]
        and info["embedded_mac_matches_header"]
        and info["advertised_ip_matches_target"]
    ):
        return identity
    if (
        power_state(data, peer, target, identity, {int.from_bytes(data[10:12], "big")})
        is not None
    ):
        return identity
    return None


def legacy_frame(identity, payload, sequence):
    mac, company, auth = identity
    return (
        b"\xa1\x04"
        + mac
        + bytes((len(payload) + 7, 0))
        + struct.pack("!H", sequence)
        + bytes((company, 2))
        + auth
        + payload
    )


def next_sequence(used):
    sequence = secrets.randbits(16)
    while sequence in used:
        sequence = secrets.randbits(16)
    used.add(sequence)
    return sequence


def power_state(data, peer, target, identity, sequences):
    """Only a current, identity-matching state packet can confirm a power change."""
    mac, company, auth = identity
    if (
        peer != (target, LEGACY_PORT)
        or len(data) not in {49, 81}
        or data[:1] != b"\xa1"
        or data[1] not in {4, 6}
        or data[2:8] != mac
        or data[8] + 9 != len(data)
        or data[9] != 0
        or int.from_bytes(data[10:12], "big") not in sequences
        or data[12:16] != bytes((company, 2)) + auth
        or data[16:19] != b"\x02\x5a\xa1"
    ):
        return None
    payload = data[16:]
    if len(payload) == 65:
        if payload[33:35] != b"\x5a\xa1":
            return None
        payload = payload[:1] + payload[33:]
    return {0: True, 0x11: False}.get(payload[9])


def read_power(sock, target, identity, used, expected=None, command_sequence=None):
    """Send at most three state queries; ignore ACKs and unrelated/stale states."""
    accepted = set() if command_sequence is None else {command_sequence}
    deadline = time.monotonic() + POWER_TIMEOUT
    next_query, queries, observed, states = 0.0, 0, None, 0
    while time.monotonic() < deadline:
        if queries < 3 and time.monotonic() >= next_query:
            sequence = next_sequence(used)
            accepted.add(sequence)
            sock.sendto(
                legacy_frame(identity, b"\x01\xa5\xa0\x11\x11\x00\x00", sequence),
                (target, LEGACY_PORT),
            )
            queries += 1
            next_query = time.monotonic() + 1
        ready, _, _ = select.select(
            [sock], [], [], min(0.2, max(0, deadline - time.monotonic()))
        )
        if not ready:
            continue
        data, peer = sock.recvfrom(65535)
        value = power_state(data, peer, target, identity, accepted)
        if value is not None:
            observed, states = value, states + 1
            if expected is None or observed == expected:
                break
    return {"observed_on": observed, "queries_sent": queries, "matching_states": states}


def set_power(sock, target, identity, used, desired):
    """The only write supported by this script: directed A5A0 power on/off."""
    sequence = next_sequence(used)
    inner = bytes((0xA5, 0xA0, 0x5E, 0x35 if desired else 0x11, 0))
    payload = b"\x01" + inner + bytes((sum(inner) & 255,))
    sock.sendto(legacy_frame(identity, payload, sequence), (target, LEGACY_PORT))
    result = read_power(sock, target, identity, used, desired, sequence)
    result.update(
        {
            "desired_on": desired,
            "command_sent": True,
            "confirmed": result["observed_on"] == desired,
        }
    )
    return result


def test_power(sock, target, identity, discovery_sequences):
    """Restore the original power even if the toggle times out or is interrupted."""
    result = {"status": "reading_initial_state", "restore_attempts": []}
    used = set(discovery_sequences)
    try:
        initial = read_power(sock, target, identity, used)
    except (OSError, KeyboardInterrupt) as exc:
        result.update(
            {"status": "skipped_initial_read_failed", "error": error_info(exc)}
        )
        return result
    result["initial_read"] = initial
    original = initial["observed_on"]
    if original is None:
        result["status"] = "skipped_no_confirmed_initial_state"
        return result
    result["original_on"] = original
    interrupted = False
    try:
        result["toggle"] = set_power(sock, target, identity, used, not original)
        if result["toggle"]["confirmed"]:
            time.sleep(1)  # Let the user observe the brief change before restoring.
    except (OSError, KeyboardInterrupt) as exc:
        interrupted = isinstance(exc, KeyboardInterrupt)
        result["toggle_error"] = error_info(exc)
    finally:
        # A send error/timeout cannot prove the device did not apply the command.
        result["restore_confirmed"] = False
        for _ in range(2):
            try:
                restore = set_power(sock, target, identity, used, original)
                result["restore_attempts"].append(restore)
                if restore["confirmed"]:
                    result["restore_confirmed"] = True
                    break
            except (OSError, KeyboardInterrupt) as exc:
                result["restore_attempts"].append(
                    {"error": error_info(exc), "confirmed": False}
                )
                if isinstance(exc, KeyboardInterrupt):
                    interrupted = True
                    break
    result["round_trip_confirmed"] = (
        result.get("toggle", {}).get("confirmed", False) and result["restore_confirmed"]
    )
    if not result["restore_confirmed"]:
        result["status"] = "RESTORE_NOT_CONFIRMED_CHECK_DEVICE"
    elif interrupted:
        result["status"] = "interrupted_original_state_restored"
    elif result["round_trip_confirmed"]:
        result["status"] = "passed"
    else:
        result["status"] = "toggle_not_confirmed_original_state_restored"
    return result


def route_and_broadcast(target, bind, broadcast):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        if bind:
            probe.bind((bind, 0))
        probe.connect((target, 5683))  # Route lookup only: no UDP payload is sent.
        local = probe.getsockname()[0]
    if broadcast:
        return local, broadcast, "explicit"
    if platform.system() == "Linux":
        try:
            import fcntl  # noqa: PLC0415 -- Linux-only standard library module.

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                for _, name in socket.if_nameindex():
                    interface = struct.pack("256s", name.encode()[:15])
                    try:
                        address = fcntl.ioctl(probe.fileno(), 0x8915, interface)[20:24]
                    except OSError:
                        # A down/IPv6-only interface must not hide a later match.
                        continue
                    if socket.inet_ntoa(address) == local:
                        mask = fcntl.ioctl(probe.fileno(), 0x891B, interface)[20:24]
                        network = ipaddress.IPv4Network(
                            (local, socket.inet_ntoa(mask)), strict=False
                        )
                        return (
                            local,
                            str(network.broadcast_address),
                            "interface_netmask",
                        )
        except (OSError, ImportError, AttributeError, ValueError):
            pass
    return local, "255.255.255.255", "limited_broadcast_fallback"


def neighbor_mac(target):
    """Only a complete ARP entry for this exact IP; never substitute the gateway."""
    try:
        with open("/proc/net/arp", encoding="ascii") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 6 and parts[0] == target and int(parts[2], 16) & 2:
                    mac = mac_bytes(parts[3])
                    if mac not in {bytes(6), b"\xff" * 6} and not mac[0] & 1:
                        return mac
    except (OSError, ValueError, argparse.ArgumentTypeError):
        pass
    return None


class HeaderCapture:
    """Optional host visibility; discard packet text, keep only safe UDP counters."""

    def __init__(self, target):
        self.target = target
        self.process = None
        self.threads = []
        self.ready = threading.Event()
        self.result = {
            "status": "not_started",
            "target_incoming_observations": 0,
            "target_outgoing_observations": 0,
            "incoming_source_ports": {},
            "incoming_udp_lengths": {},
            "note": "Interface observations can count the same packet more than once.",
        }

    def observe(self, line):
        match = re.search(
            r"\bIP (\d+\.\d+\.\d+\.\d+)\.(\d+) > "
            r"(\d+\.\d+\.\d+\.\d+)\.(\d+): UDP, length (\d+)",
            line,
        )
        if not match:
            return
        source, port, destination, _, length = match.groups()
        if source == self.target:
            self.result["target_incoming_observations"] += 1
            for name, value in (
                ("incoming_source_ports", port),
                ("incoming_udp_lengths", length),
            ):
                histogram = self.result[name]
                # Fixed bound even if unrelated/malicious traffic hits this IP.
                key = value if value in histogram or len(histogram) < 32 else "other"
                histogram[key] = histogram.get(key, 0) + 1
        if destination == self.target:
            self.result["target_outgoing_observations"] += 1

    def start(self):
        executable = shutil.which("tcpdump")
        if platform.system() != "Linux" or not executable:
            self.result["status"] = "unavailable"
            return
        try:
            self.process = subprocess.Popen(
                [
                    executable,
                    "-n",
                    "-i",
                    "any",
                    "-l",
                    "-tt",
                    "-q",
                    "-s",
                    "96",
                    "udp and host " + self.target,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="ascii",
                errors="replace",
                env=dict(os.environ, LC_ALL="C"),
            )
        except OSError as exc:
            self.result.update(status="start_failed", error=error_info(exc))
            return

        def stdout():
            for line in self.process.stdout:
                self.observe(line)

        def stderr():
            for line in self.process.stderr:
                if "listening on" in line:
                    self.result["status"] = "listening"
                    self.ready.set()
                elif "permission" in line.lower() or "permitted" in line.lower():
                    self.result["status"] = "permission_denied"
                elif "dropped by kernel" in line:
                    match = re.match(r"(\d+) packets dropped by kernel", line)
                    if match:
                        self.result["kernel_drops"] = int(match[1])
            self.ready.set()

        self.result["status"] = "starting"
        for reader in (stdout, stderr):
            thread = threading.Thread(target=reader, daemon=True)
            self.threads.append(thread)
            thread.start()
        self.ready.wait(1)

    def stop(self):
        if self.process:
            self.result["exited_before_scan_finished"] = self.process.poll() is not None
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
            for thread in self.threads:
                thread.join(timeout=1)
            for stream in (self.process.stdout, self.process.stderr):
                stream.close()
            if self.result["status"] == "starting":
                self.result["status"] = "no_listening_confirmation"
            elif self.result["status"] == "listening":
                self.result["status"] = "captured"
        return self.result


def legacy_probes(target, broadcast, mac, sequences):
    """Finite compatibility matrix; all payloads here are discovery/state reads."""
    for index, auth in enumerate((b"\xcb\x76", b"\x04\x03", b"\x05\x04")):
        suffix = "" if index == 0 else "_seed_" + str(index + 1)
        for name, host, address, operation in (
            ("legacy_unicast", target, mac or b"\xff" * 6, 4),
            ("legacy_broadcast_00", broadcast, b"\xff" * 6, 0),
            ("legacy_broadcast_04", broadcast, b"\xff" * 6, 4),
        ):
            sequence = next_sequence(sequences)
            packet = (
                bytes((0xA1, operation))
                + address
                + b"\x08\x00"
                + struct.pack("!H", sequence)
                + b"\xf1\x02"
                + auth
                + b"\x23"
            )
            yield name + suffix, packet, host
        if mac:
            yield (
                "legacy_state_seed_" + str(index + 1),
                legacy_frame(
                    (mac, 0xF1, auth),
                    b"\x01\xa5\xa0\x11\x11\x00\x00",
                    next_sequence(sequences),
                ),
                target,
            )
    for wire_type in (1, 3, 4):
        packet = (
            b"\xa1\x04"
            + (mac or b"\xff" * 6)
            + b"\x08\x00"
            + struct.pack("!H", next_sequence(sequences))
            + bytes((0xF1, wire_type))
            + b"\xcb\x76\x23"
        )
        yield "legacy_other_type_" + str(wire_type), packet, target


def open_channel(channel, local, report):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if channel == "coap":
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local)
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.bind((local, 0))
        else:
            try:
                sock.bind(("0.0.0.0", LEGACY_PORT))
                report["legacy_fixed_port"] = {"bound": True}
            except OSError as exc:
                report["legacy_fixed_port"] = {
                    "bound": False,
                    "error": error_info(exc),
                    "limitation": "replies to 11530 may go to HA",
                }
                sock.bind((local, 0))
        sock.setblocking(False)
        return sock
    except OSError as exc:
        report.setdefault("channel_errors", {})[channel] = error_info(exc)
        if sock is not None:
            sock.close()
        return None


def run(args):
    report = {
        "script_version": VERSION,
        "label": args.label,
        "status": "starting",
        "python": ".".join(str(x) for x in sys.version_info[:3]),
        "system": platform.system(),
        "machine": platform.machine(),
        "runtime": (
            "host_ha_container"
            if os.environ.get("PROBE_RUNTIME") == "host_ha_container"
            else "host_python"
            if os.environ.get("PROBE_RUNTIME") == "host_python"
            else "direct_python"
        ),
        "docker_marker_present": os.path.exists("/.dockerenv"),
        "target": "TARGET_IP",
        "expected_mac_supplied": args.mac is not None,
        "legacy_wire_type": 2,
        "power_test": {"status": "not_run"},
        "planned_seconds": args.seconds,
        "probes": {},
        "responses": [],
        "receive": {"target": 0, "other": 0, "self_echo": 0},
        "privacy": "IP/MAC/deviceName/tokens/auth/raw payload omitted",
    }
    started = time.monotonic()
    sockets, requests, sequences, identities = [], {}, set(), set()
    counts = collections.Counter()
    seen = set()
    selector = selectors.DefaultSelector()
    capture = HeaderCapture(args.target)
    expected_mac = args.mac
    try:
        local, broadcast, mode = route_and_broadcast(
            args.target, args.bind, args.broadcast
        )
        report["network"] = {
            "sender": "LOCAL_IP",
            "broadcast_mode": mode,
            "target_equals_sender": args.target == local,
        }
        capture.start()
        coap = open_channel("coap", local, report)
        legacy = open_channel("legacy", local, report)
        report["source_ports"] = {}
        for sock, channel in ((coap, "coap"), (legacy, "legacy")):
            if sock is None:
                continue
            sockets.append(sock)
            selector.register(sock, selectors.EVENT_READ, channel)
            report["source_ports"][channel] = sock.getsockname()[1]
        if not sockets:
            raise OSError("No usable UDP channel")
        plan = [
            ("info_unicast", "info", args.target, "TARGET_IP", False),
            ("info_broadcast", "info", broadcast, "BROADCAST", False),
            ("alcs_unicast", "alcs", args.target, "TARGET_IP", False),
            ("alcs_multicast", "alcs", "224.0.1.187", "ALCS_GROUP", False),
            ("alcs_broadcast", "alcs", broadcast, "BROADCAST", False),
            ("info_unicast_con", "info", args.target, "TARGET_IP", True),
            ("alcs_unicast_con", "alcs", args.target, "TARGET_IP", True),
        ]
        report["status"] = "complete"
        round_number = 0
        active_started = time.monotonic()
        deadline = active_started + args.seconds
        while time.monotonic() < deadline:
            elapsed = time.monotonic() - active_started
            if round_number < 3 and elapsed >= round_number * 5:
                round_number += 1
                outgoing = []
                if expected_mac is None:
                    expected_mac = neighbor_mac(args.target)
                report["mac_source"] = (
                    "argument"
                    if args.mac
                    else "arp_cache"
                    if expected_mac
                    else "unknown"
                )
                for name, kind, host, alias, confirmable in plan:
                    token, mid, request_id = (
                        secrets.token_bytes(8),
                        secrets.randbits(16),
                        str(secrets.randbits(32)),
                    )
                    requests[token] = {"name": name, "id": request_id, "mid": mid}
                    outgoing.append(
                        (
                            name,
                            coap,
                            coap_request(kind, token, mid, request_id, confirmable),
                            host,
                            5683,
                            alias,
                        )
                    )
                for name, packet, host in legacy_probes(
                    args.target, broadcast, expected_mac, sequences
                ):
                    outgoing.append(
                        (
                            name,
                            legacy,
                            packet,
                            host,
                            11530,
                            "TARGET_IP" if host == args.target else "BROADCAST",
                        )
                    )
                for name, sock, packet, host, port, alias in outgoing:
                    summary = report["probes"].setdefault(
                        name,
                        {
                            "destination": alias,
                            "port": port,
                            "sent": 0,
                            "errors": [],
                            "request_lengths": [],
                        },
                    )
                    if len(packet) not in summary["request_lengths"]:
                        summary["request_lengths"].append(len(packet))
                    if sock is None:
                        summary["skipped"] = "channel_unavailable"
                        continue
                    try:
                        sock.sendto(packet, (host, port))
                        summary["sent"] += 1
                    except OSError as exc:
                        summary["errors"].append(error_info(exc))
            for key, _ in selector.select(
                min(0.25, max(0, deadline - time.monotonic()))
            ):
                try:
                    data, peer = key.fileobj.recvfrom(65535)
                except OSError as exc:
                    report.setdefault("receive_errors", []).append(error_info(exc))
                    continue
                relation = (
                    "target"
                    if peer[0] == args.target
                    else "self_echo"
                    if peer[0] == local
                    else "other"
                )
                report["receive"][relation] += 1
                if relation == "target":
                    if data[:1] == b"\xa1":
                        detail = read_legacy(data, sequences, args.target, expected_mac)
                        identity = legacy_identity(
                            data, peer, args.target, expected_mac, sequences
                        )
                        if identity is not None:
                            identities.add(identity)
                        ack = None
                    else:
                        detail, ack = read_coap(data, requests)
                    if ack:
                        try:
                            key.fileobj.sendto(ack, peer)
                        except OSError:
                            counts["ack_send_errors"] += 1
                    detail.update(
                        {
                            "channel": key.data,
                            "source": "TARGET_IP",
                            "source_port": peer[1],
                            "bytes": len(data),
                        }
                    )
                    counts[detail.get("probe", detail["format"])] += 1
                    fingerprint = json.dumps(detail, sort_keys=True)
                    if (
                        fingerprint not in seen
                        and len(report["responses"]) < MAX_DETAILS
                    ):
                        seen.add(fingerprint)
                        detail["first_seen_seconds"] = round(
                            time.monotonic() - started, 3
                        )
                        report["responses"].append(detail)
                    elif fingerprint not in seen:
                        counts["detail_limit_omitted_packets"] += 1
            if sum(report["receive"].values()) >= MAX_PACKETS:
                report["status"] = "receive_limit_reached"
                break
        if report["status"] == "complete":
            if args.target == local:
                report["power_test"] = {"status": "skipped_target_is_sender"}
            elif len(identities) == 1 and legacy is not None:
                print(
                    "Verified legacy device: reading power, toggling, then restoring.",
                    file=sys.stderr,
                )
                report["power_test"] = test_power(
                    legacy, args.target, next(iter(identities)), sequences
                )
            else:
                report["power_test"] = {
                    "status": "skipped_conflicting_identity"
                    if identities
                    else "skipped_no_verified_control_protocol",
                    "reason": (
                        "CoAP discovery alone is not an authorized control session; "
                        "legacy testing requires a validated type-2 target reply."
                    ),
                }
    except KeyboardInterrupt:
        report["status"] = "interrupted"
    except OSError as exc:
        report["status"] = "setup_or_socket_error"
        report["error"] = error_info(exc)
    finally:
        report["host_capture"] = capture.stop()
        selector.close()
        for sock in sockets:
            sock.close()
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    if report["power_test"]["status"] == "not_run":
        report["power_test"]["status"] = "skipped_scan_incomplete"
    report["target_response_counts"] = dict(counts)
    if report["power_test"].get("restore_confirmed") is False:
        report["interpretation"] = (
            "Power restoration was not confirmed; check the device."
        )
    elif report["power_test"]["status"] == "passed":
        report["interpretation"] = (
            "Power toggle and original-state restoration "
            "confirmed by fresh device states."
        )
    elif report.get("network", {}).get("target_equals_sender"):
        report["interpretation"] = (
            "Target equals the local sender address; check the device IP."
        )
    elif not report["receive"]["target"]:
        if report["host_capture"]["target_incoming_observations"]:
            report["interpretation"] = (
                "Host capture saw target UDP but this script received none. "
                "Review destination ports, HA listener and host/container routing."
            )
        else:
            report["interpretation"] = (
                "No target datagram observed; this does not prove "
                "the device lacks local support. Check host_capture coverage."
            )
    else:
        report["interpretation"] = (
            "Target traffic observed. Review correlation, response codes and identity "
            "structure; discovery is not control authorization."
        )
    return report


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--check-runtime",
        action="store_true",
        help="Offline startup check; sends no packets",
    )
    parser.add_argument(
        "target", nargs="?", type=ipv4, help="Current device IPv4 (not printed)"
    )
    parser.add_argument(
        "control",
        nargs="?",
        type=ipv4,
        help="Optional ordinary X83C IPv4 for a second test",
    )
    parser.add_argument("--label", choices=("plus", "x83c", "other"), default="plus")
    parser.add_argument("--mac", type=mac_bytes, help="Optional MAC, never printed")
    parser.add_argument("--bind", type=ipv4, help="Optional NAS/source IPv4")
    parser.add_argument("--broadcast", type=ipv4, help="Optional subnet broadcast IPv4")
    parser.add_argument(
        "--seconds", type=int, default=45, help="Listen 5-90 seconds (default 45)"
    )
    args = parser.parse_args()
    if args.check_runtime:
        # Imports above plus a parser/serializer exercise, without network I/O.
        if sys.version_info < (3, 8):  # noqa: UP036 -- Standalone NAS Python baseline.
            parser.error("Python 3.8 or newer is required")
        packet = coap_request("info", b"12345678", 1, "1")
        detail, _ = read_coap(packet, {})
        print(
            json.dumps(
                {
                    "status": "runtime_ok",
                    "script_version": VERSION,
                    "python": platform.python_version(),
                    "parser": detail["parse"],
                }
            )
        )
        return 0
    if (
        not args.target
        or args.target == "255.255.255.255"
        or not 5 <= args.seconds <= 90
    ):
        parser.error("Use a host target and a duration between 5 and 90 seconds")
    if args.control in {args.target, "255.255.255.255"}:
        parser.error("Control must be a different host IPv4")
    print(
        "Discovery followed by an automatic power toggle/restore if verified. "
        "Review the redacted JSON before sharing.",
        file=sys.stderr,
    )
    reports = [run(args)]
    if (
        args.control
        and reports[0]["status"] != "interrupted"
        and not reports[0]["power_test"]["status"].startswith("interrupted")
        and reports[0]["power_test"].get("restore_confirmed") is not False
    ):
        args.target, args.label, args.mac = args.control, "x83c", None
        reports.append(run(args))
    output = (
        reports[0]
        if not args.control
        else {"script_version": VERSION, "devices": reports}
    )
    print(json.dumps(output, ensure_ascii=True, indent=2))
    if any(
        report["power_test"].get("restore_confirmed") is False for report in reports
    ):
        print(
            "POWER RESTORE NOT CONFIRMED: check the device power manually.",
            file=sys.stderr,
        )
        return 2
    return (
        1
        if any(report["status"] == "setup_or_socket_error" for report in reports)
        else 0
    )


if __name__ == "__main__":
    sys.exit(main())
