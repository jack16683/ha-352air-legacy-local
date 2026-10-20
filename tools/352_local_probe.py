#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Standalone 352 LAN diagnostics. Python 3.8+, standard library only.

Run on the NAS host, not inside the OpenClaw container:
  python3 352_local_probe.py DEVICE_IP --label plus > plus-result.txt
Optional: --mac AA:BB:CC:DD:EE:FF --bind NAS_IP --broadcast SUBNET_BROADCAST

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
import socket
import struct
import sys
import time

VERSION = "1.1"
LEGACY_PORT = 11530
POWER_TIMEOUT = 4.0
MAX_DETAILS = 24
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
    if key == "method" and value in {item[1] for item in PATHS.values()}:
        return value
    if key == "pal" and value in ("linkkit", "alink"):
        return value
    if value is None:
        return None
    return redacted(value)


def coap_request(kind, token, mid, request_id):
    path, method = PATHS[kind]
    payload = json.dumps(
        {"id": request_id, "version": "1.0", "method": method, "params": {}},
        separators=(",", ":"),
    ).encode()
    result = bytearray(b"\x58\x01" + struct.pack("!H", mid) + token)
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
    detail = {
        "format": "coap",
        "type": ("CON", "NON", "ACK", "RST")[(data[0] >> 4) & 3],
        "code": f"{data[1] >> 5}.{data[1] & 31:02d}",
        "token_bytes": length,
        "token_matches_request": request is not None,
        "probe": request["name"] if request else "unmatched",
    }
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


def run(args):
    report = {
        "script_version": VERSION,
        "label": args.label,
        "status": "starting",
        "python": ".".join(str(x) for x in sys.version_info[:3]),
        "system": platform.system(),
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
    try:
        local, broadcast, mode = route_and_broadcast(
            args.target, args.bind, args.broadcast
        )
        report["network"] = {
            "sender": "LOCAL_IP",
            "broadcast_mode": mode,
            "target_equals_sender": args.target == local,
        }
        coap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockets.append(coap)
        coap.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        coap.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local)
        )
        coap.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        coap.bind((local, 0))
        legacy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockets.append(legacy)
        legacy.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            legacy.bind(("0.0.0.0", 11530))
            report["legacy_fixed_port"] = {"bound": True}
        except OSError as exc:
            report["legacy_fixed_port"] = {
                "bound": False,
                "error": error_info(exc),
                "limitation": "replies to 11530 may go to HA",
            }
            legacy.bind((local, 0))
        for sock, channel in ((coap, "coap"), (legacy, "legacy")):
            sock.setblocking(False)
            selector.register(sock, selectors.EVENT_READ, channel)
        report["source_ports"] = {
            "coap": coap.getsockname()[1],
            "legacy": legacy.getsockname()[1],
        }
        plan = [
            ("info_unicast", "info", args.target, "TARGET_IP"),
            ("info_broadcast", "info", broadcast, "BROADCAST"),
            ("alcs_unicast", "alcs", args.target, "TARGET_IP"),
            ("alcs_multicast", "alcs", "224.0.1.187", "ALCS_GROUP"),
            ("alcs_broadcast", "alcs", broadcast, "BROADCAST"),
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
                for name, kind, host, alias in plan:
                    token, mid, request_id = (
                        secrets.token_bytes(8),
                        secrets.randbits(16),
                        str(secrets.randbits(32)),
                    )
                    requests[token] = {"name": name, "id": request_id}
                    outgoing.append(
                        (
                            name,
                            coap,
                            coap_request(kind, token, mid, request_id),
                            host,
                            5683,
                            alias,
                        )
                    )
                for name, host, mac, operation in (
                    ("legacy_unicast", args.target, args.mac or b"\xff" * 6, 4),
                    ("legacy_broadcast_00", broadcast, b"\xff" * 6, 0),
                    ("legacy_broadcast_04", broadcast, b"\xff" * 6, 4),
                ):
                    sequence = secrets.randbits(16)
                    sequences.add(sequence)
                    packet = (
                        bytes((0xA1, operation))
                        + mac
                        + b"\x08\x00"
                        + struct.pack("!H", sequence)
                        + b"\xf1\x02\xcb\x76\x23"
                    )
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
                        detail = read_legacy(data, sequences, args.target, args.mac)
                        identity = legacy_identity(
                            data, peer, args.target, args.mac, sequences
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
            if sum(report["receive"].values()) >= MAX_PACKETS:
                report["status"] = "receive_limit_reached"
                break
        if report["status"] == "complete":
            if args.target == local:
                report["power_test"] = {"status": "skipped_target_is_sender"}
            elif len(identities) == 1:
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
        report["interpretation"] = (
            "No target datagram observed; this does not prove "
            "the device lacks local support."
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
    parser.add_argument("target", type=ipv4, help="Current device IPv4 (not printed)")
    parser.add_argument("--label", choices=("plus", "x83c", "other"), default="plus")
    parser.add_argument("--mac", type=mac_bytes, help="Optional MAC, never printed")
    parser.add_argument("--bind", type=ipv4, help="Optional NAS/source IPv4")
    parser.add_argument("--broadcast", type=ipv4, help="Optional subnet broadcast IPv4")
    parser.add_argument(
        "--seconds", type=int, default=45, help="Listen 5-90 seconds (default 45)"
    )
    args = parser.parse_args()
    if args.target == "255.255.255.255" or not 5 <= args.seconds <= 90:
        parser.error("Use a host target and a duration between 5 and 90 seconds")
    print(
        "Discovery followed by an automatic power toggle/restore if verified. "
        "Review the redacted JSON before sharing.",
        file=sys.stderr,
    )
    report = run(args)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    if report["power_test"].get("restore_confirmed") is False:
        print(
            "POWER RESTORE NOT CONFIRMED: check the device power manually.",
            file=sys.stderr,
        )
        return 2
    return 1 if report["status"] == "setup_or_socket_error" else 0


if __name__ == "__main__":
    sys.exit(main())
