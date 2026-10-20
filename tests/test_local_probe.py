"""Synthetic and real loopback checks for the standalone shareable script."""

import ast
import errno
import importlib.util
import io
import json
import os
import random
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import mock_open, patch

SCRIPT = Path(__file__).resolve().parents[1] / "tools/352_local_probe.py"
spec = importlib.util.spec_from_file_location("standalone_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
REAL_SOCKET = socket.socket
TOKEN = b"12345678"
PK = "a1TNKV3wr7I"
PRIVATE = "PRIVATE_FIXTURE_SECRET"
MAC = bytes.fromhex("123456789abc")


def request_parts(packet):
    assert packet[:2] in {b"\x58\x01", b"\x48\x01"}
    token = packet[4:12]
    offset, number, parts = 12, 0, []
    while packet[offset] != 255:
        h = packet[offset]
        offset += 1
        number += h >> 4
        length = h & 15
        assert length < 13 and h >> 4 < 13
        value = packet[offset : offset + length]
        offset += length
        if number == 11:
            parts.append(value.decode())
    return token, "/" + "/".join(parts), json.loads(packet[offset + 1 :])


def coap_reply(token, payload, code=69):
    return (
        bytes([0x58, code, 2, 3])
        + token
        + b"\xc1\x32\xff"
        + json.dumps(payload).encode()
    )


probe.HeaderCapture.start = lambda self: None


def args(seconds=45):
    return SimpleNamespace(
        target="192.0.2.123",
        label="plus",
        mac=MAC,
        bind=None,
        broadcast=None,
        seconds=seconds,
    )


IDENTITY = (MAC, 0xF1, b"\x12\x34")


def state_packet(on, sequence, mac=MAC):
    payload = bytearray(33)
    payload[:3] = b"\x02\x5a\xa1"
    payload[9] = 0 if on else 0x11
    return (
        b"\xa1\x06"
        + mac
        + b"\x28\x00"
        + struct.pack("!H", sequence)
        + b"\xf1\x02\x12\x34"
        + payload
    )


class PowerTests(unittest.TestCase):
    def exercise(
        self,
        original=False,
        baseline=True,
        ignore_toggle=False,
        ignore_restore=False,
        interrupt=False,
        send_error=False,
    ):
        clock = [0.0]
        commands = []
        queue = []

        class Device:
            on = original

            def sendto(self, data, peer):
                self.assert_peer = peer
                payload = data[16:]
                sequence = int.from_bytes(data[10:12], "big")
                if payload == b"\x01\xa5\xa0\x11\x11\x00\x00":
                    if baseline or commands:
                        queue.append(state_packet(self.on, sequence))
                    return
                assert payload[:4] == b"\x01\xa5\xa0\x5e"
                assert payload[-1] == sum(payload[1:6]) & 255
                commands.append(payload[4])
                if (len(commands) == 1 and not ignore_toggle) or (
                    len(commands) > 1 and not ignore_restore
                ):
                    self.on = payload[4] == 0x35
                if send_error and len(commands) == 1:
                    raise OSError(errno.EIO, PRIVATE)

            def recvfrom(self, _size):
                return queue.pop(0), ("192.0.2.123", probe.LEGACY_PORT)

        device = Device()

        def select(read, _write, _error, timeout):
            if queue:
                return read, [], []
            clock[0] += timeout
            return [], [], []

        def sleep(seconds):
            if interrupt:
                raise KeyboardInterrupt
            clock[0] += seconds

        with (
            patch.object(probe.time, "monotonic", lambda: clock[0]),
            patch.object(probe.time, "sleep", sleep),
            patch.object(probe.select, "select", side_effect=select),
        ):
            result = probe.test_power(device, "192.0.2.123", IDENTITY, {42})
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn("192.0.2.123", json.dumps(result))
        return result, commands, device.on

    def test_round_trip_off_on_off_and_on_off_on(self):
        for initial in (False, True):
            result, commands, final = self.exercise(original=initial)
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["round_trip_confirmed"])
            self.assertEqual(final, initial)
            self.assertEqual(commands, [0x11, 0x35] if initial else [0x35, 0x11])

    def test_no_initial_state_means_no_write(self):
        result, commands, _ = self.exercise(baseline=False)
        self.assertEqual(result["status"], "skipped_no_confirmed_initial_state")
        self.assertEqual(commands, [])

    def test_ignored_toggle_is_not_reported_as_success(self):
        result, commands, final = self.exercise(ignore_toggle=True)
        self.assertFalse(result["round_trip_confirmed"])
        self.assertTrue(result["restore_confirmed"])
        self.assertEqual(
            result["status"], "toggle_not_confirmed_original_state_restored"
        )
        self.assertFalse(final)
        self.assertEqual(len(commands), 2)

    def test_failed_restore_is_explicit_and_bounded(self):
        result, commands, final = self.exercise(ignore_restore=True)
        self.assertEqual(result["status"], "RESTORE_NOT_CONFIRMED_CHECK_DEVICE")
        self.assertFalse(result["restore_confirmed"])
        self.assertEqual(commands, [0x35, 0x11, 0x11])
        self.assertTrue(final)

    def test_interrupt_restores_original_power(self):
        result, commands, final = self.exercise(interrupt=True)
        self.assertEqual(result["status"], "interrupted_original_state_restored")
        self.assertTrue(result["restore_confirmed"])
        self.assertEqual(commands, [0x35, 0x11])
        self.assertFalse(final)

    def test_uncertain_send_error_still_restores(self):
        result, commands, final = self.exercise(send_error=True)
        self.assertFalse(result["round_trip_confirmed"])
        self.assertTrue(result["restore_confirmed"])
        self.assertEqual(commands, [0x35, 0x11])
        self.assertFalse(final)

    def test_power_requires_current_sequence_identity_and_state_not_ack(self):
        valid = state_packet(False, 99)
        self.assertIs(
            probe.power_state(
                valid, ("192.0.2.123", 11530), "192.0.2.123", IDENTITY, {99}
            ),
            False,
        )
        for packet, peer, sequence in (
            (valid, ("192.0.2.124", 11530), 99),
            (valid, ("192.0.2.123", 9999), 99),
            (valid, ("192.0.2.123", 11530), 100),
            (state_packet(False, 99, mac=b"\x22" * 6), ("192.0.2.123", 11530), 99),
            (valid[:14] + b"\x99\x99" + valid[16:], ("192.0.2.123", 11530), 99),
            (valid[:25] + b"\x35" + valid[26:], ("192.0.2.123", 11530), 99),
        ):
            self.assertIsNone(
                probe.power_state(packet, peer, "192.0.2.123", IDENTITY, {sequence})
            )

    def test_identity_learning_does_not_use_unmatched_discovery(self):
        body = b"\x23" + socket.inet_aton("192.0.2.123") + MAC
        packet = b"\xa1\x06" + MAC + b"\x12\x00\x00\x2a\xf1\x02\x12\x34" + body
        self.assertEqual(
            probe.legacy_identity(
                packet, ("192.0.2.123", 11530), "192.0.2.123", MAC, {42}
            ),
            IDENTITY,
        )
        self.assertIsNone(
            probe.legacy_identity(
                packet, ("192.0.2.123", 11530), "192.0.2.123", MAC, {43}
            )
        )
        self.assertIsNone(
            probe.legacy_identity(
                packet, ("192.0.2.124", 11530), "192.0.2.123", MAC, {42}
            )
        )

    def test_power_control_over_actual_loopback_udp(self):
        server = REAL_SOCKET(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.02)
        port = server.getsockname()[1]
        stop = threading.Event()
        commands, errors = [], []
        state = [False]

        def serve():
            while not stop.is_set():
                try:
                    packet, peer = server.recvfrom(65535)
                except TimeoutError:
                    continue
                try:
                    payload = packet[16:]
                    if payload == b"\x01\xa5\xa0\x11\x11\x00\x00":
                        server.sendto(
                            state_packet(
                                state[0], int.from_bytes(packet[10:12], "big")
                            ),
                            peer,
                        )
                    else:
                        assert payload[:4] == b"\x01\xa5\xa0\x5e"
                        assert payload[-1] == sum(payload[1:6]) & 255
                        commands.append(payload[4])
                        state[0] = payload[4] == 0x35
                except Exception as exc:
                    errors.append(exc)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = REAL_SOCKET(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.setblocking(False)
        try:
            with (
                patch.object(probe, "LEGACY_PORT", port),
                patch.object(probe, "POWER_TIMEOUT", 1),
                patch.object(probe.time, "sleep", lambda _seconds: None),
            ):
                result = probe.test_power(client, "127.0.0.1", IDENTITY, set())
        finally:
            client.close()
            stop.set()
            thread.join(1)
            server.close()
        self.assertEqual(errors, [])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(commands, [0x35, 0x11])
        self.assertFalse(state[0])


class UnitTests(unittest.TestCase):
    def test_python38_syntax(self):
        ast.parse(SCRIPT.read_text(), feature_version=(3, 8))

    def test_linux_interface_without_ipv4_does_not_hide_sender_subnet(self):
        class RouteSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def connect(self, _peer):
                pass

            def getsockname(self):
                return "192.0.2.1", 40000

            def fileno(self):
                return 10

        def ioctl(_fd, operation, interface):
            name = interface.split(b"\x00")[0]
            if name == b"empty":
                raise OSError(errno.EADDRNOTAVAIL, "fixture")
            address = (
                "255.255.254.0"
                if operation == 0x891B
                else "127.0.0.1"
                if name == b"lo"
                else "192.0.2.1"
            )
            return bytes(20) + socket.inet_aton(address)

        with (
            patch.object(probe.platform, "system", return_value="Linux"),
            patch.object(probe.socket, "socket", return_value=RouteSocket()),
            patch.object(
                probe.socket,
                "if_nameindex",
                return_value=[(1, "lo"), (2, "empty"), (3, "eth0")],
            ),
            patch("fcntl.ioctl", side_effect=ioctl),
        ):
            result = probe.route_and_broadcast("192.0.2.123", None, None)
        self.assertEqual(result, ("192.0.2.1", "192.0.3.255", "interface_netmask"))

    def test_private_fields_and_unknown_keys_never_echo(self):
        payload = {
            "id": PRIVATE,
            "code": 200,
            "data": {
                "productKey": PK,
                "deviceName": PRIVATE,
                "ip": "192.0.2.123",
                "mac": "12:34:56:78:9a:bc",
                "token": PRIVATE,
                "accessToken": PRIVATE,
                "random": PRIVATE,
                PRIVATE: PRIVATE,
                "fwVersion": "1.6.3_EMC3080P",
            },
        }
        text = json.dumps(probe.safe_payload(payload))
        for secret in (PRIVATE, "192.0.2.123", "12:34:56:78:9a:bc"):
            self.assertNotIn(secret, text)
        self.assertIn(PK, text)
        self.assertIn("1.6.3_EMC3080P", text)
        self.assertNotIn(
            PRIVATE, json.dumps(probe.error_info(OSError(errno.EIO, PRIVATE)))
        )

    def test_coap_error_reply_correlation_and_shape(self):
        request = {TOKEN: {"name": "info_unicast", "id": "7"}}
        error = {"id": "7", "code": 401, "message": PRIVATE}
        detail, ack = probe.read_coap(coap_reply(TOKEN, error, code=129), request)
        self.assertEqual(detail["code"], "4.01")
        self.assertTrue(detail["token_matches_request"])
        self.assertTrue(detail["json_id_matches_request"])
        self.assertFalse(detail["correlated_success_response"])
        self.assertNotIn(PRIVATE, json.dumps(detail))
        self.assertIsNone(ack)
        other, _ = probe.read_coap(coap_reply(b"87654321", error), request)
        self.assertFalse(other["token_matches_request"])

    def test_legacy_reply_preserves_structure_not_identity(self):
        payload = b"\x23" + socket.inet_aton("192.0.2.123") + MAC
        packet = b"\xa1\x06" + MAC + b"\x12\x00\x00\x2a\xf1\x02\x12\x34" + payload
        detail = probe.read_legacy(packet, {42}, "192.0.2.123", MAC)
        self.assertTrue(detail["outer_length_valid"])
        self.assertTrue(detail["embedded_mac_matches_header"])
        self.assertTrue(detail["mac_matches_input"])
        self.assertEqual(detail["payload_kind"], "discovery_reply")
        text = json.dumps(detail)
        self.assertNotIn("192.0.2.123", text)
        self.assertNotIn("12:34:56", text)
        self.assertEqual(detail["auth"], "<redacted>")

    def test_malformed_packets_and_nested_values_do_not_crash(self):
        rng = random.Random(352)
        for _ in range(1000):
            probe.read_coap(rng.randbytes(rng.randrange(0, 100)), {})
        for value in ([], {}, None, True, 42, {"method": []}, {"data": {"method": {}}}):
            probe.safe_payload(value)
        packet = b"\x58\x45\x00\x01" + TOKEN + b"\xff" + b"[" * 1200
        detail, _ = probe.read_coap(packet, {})
        self.assertEqual(detail["parse"], "malformed_options_or_json")

    def simulate(self, busy=False, interrupt=False, with_identity=False):
        clock = [0.0]
        created = []
        sent = []

        class Sock:
            def __init__(self, *_a):
                self.port, self.closed = 40000 + len(created), False
                self.queue = []
                created.append(self)

            def setsockopt(self, level, option, value):
                assert option not in {
                    socket.SO_REUSEADDR,
                    getattr(socket, "SO_REUSEPORT", -1),
                }

            def setblocking(self, _value):
                pass

            def bind(self, address):
                if busy and address[1] == 11530:
                    raise OSError(errno.EADDRINUSE, PRIVATE)
                self.port = address[1] or self.port

            def getsockname(self):
                return "192.0.2.1", self.port

            def sendto(self, packet, peer):
                sent.append((packet, peer))
                if with_identity and peer == ("192.0.2.123", 11530):
                    body = b"\x23" + socket.inet_aton("192.0.2.123") + MAC
                    reply = b"\xa1\x06" + MAC + b"\x12\x00" + packet[10:12]
                    reply += b"\xf1\x02\x12\x34" + body
                    self.queue.append((reply, peer))

            def recvfrom(self, _size):
                return self.queue.pop(0)

            def close(self):
                self.closed = True

        class Selector:
            def __init__(self):
                self.keys = []

            def register(self, sock, _events, channel):
                self.keys.append(SimpleNamespace(fileobj=sock, data=channel))

            def select(self, timeout):
                if interrupt:
                    raise KeyboardInterrupt
                clock[0] += timeout
                return [(key, 1) for key in self.keys if key.fileobj.queue]

            def close(self):
                pass

        with (
            patch.object(probe.socket, "socket", Sock),
            patch.object(probe.selectors, "DefaultSelector", Selector),
            patch.object(probe.time, "monotonic", lambda: clock[0]),
            patch.object(
                probe,
                "route_and_broadcast",
                return_value=("192.0.2.1", "192.0.2.255", "fixture"),
            ),
        ):
            result = probe.run(args())
        self.assertTrue(all(s.closed for s in created))
        return result, sent

    def test_full_duration_is_bounded_read_only_and_includes_every_case(self):
        report, sent = self.simulate()
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(sent), 66)
        self.assertEqual(len(report["probes"]), 22)
        self.assertTrue(all(p["sent"] == 3 for p in report["probes"].values()))
        for packet, peer in sent:
            if peer[1] == 11530:
                self.assertIn(packet[16:], {b"\x23", b"\x01\xa5\xa0\x11\x11\x00\x00"})
            else:
                token, path, payload = request_parts(packet)
                self.assertEqual(len(token), 8)
                self.assertIn(path, {v[0] for v in probe.PATHS.values()})
                self.assertEqual(payload["params"], {})
        self.assertNotIn("192.0.2.", json.dumps(report))

    def test_default_run_starts_power_test_after_verified_discovery(self):
        with patch.object(
            probe,
            "test_power",
            return_value={"status": "passed", "restore_confirmed": True},
        ) as power:
            report, _ = self.simulate(with_identity=True)
        power.assert_called_once()
        self.assertEqual(power.call_args.args[2], IDENTITY)
        self.assertEqual(report["power_test"]["status"], "passed")
        self.assertNotIn("192.0.2.", json.dumps(report))

    def test_busy_legacy_port_is_explicit_not_a_false_negative(self):
        report, _ = self.simulate(busy=True)
        self.assertFalse(report["legacy_fixed_port"]["bound"])
        self.assertIn("HA", report["legacy_fixed_port"]["limitation"])
        self.assertNotEqual(report["source_ports"]["legacy"], 11530)
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_interrupt_still_returns_partial_report_and_closes_sockets(self):
        report, _ = self.simulate(interrupt=True)
        self.assertEqual(report["status"], "interrupted")

    def test_actual_udp_loopback_for_coap_and_legacy(self):
        """Map all test destinations to loopback: no multicast or LAN packets."""
        coap = REAL_SOCKET(socket.AF_INET, socket.SOCK_DGRAM)
        legacy = REAL_SOCKET(socket.AF_INET, socket.SOCK_DGRAM)
        for server in (coap, legacy):
            server.bind(("127.0.0.1", 0))
            server.settimeout(0.02)
        coap_port, legacy_port = coap.getsockname()[1], legacy.getsockname()[1]
        stop = threading.Event()
        failures = []

        def serve(server, is_coap):
            while not stop.is_set():
                try:
                    packet, peer = server.recvfrom(65535)
                except TimeoutError:
                    continue
                try:
                    if is_coap:
                        token, _, request = request_parts(packet)
                        payload = {
                            "id": request["id"],
                            "code": 200,
                            "data": {
                                "productKey": PK,
                                "deviceName": PRIVATE,
                                "token": PRIVATE,
                                "ip": "127.0.0.1",
                                "mac": "12:34:56:78:9a:bc",
                                "fwVersion": "1.6.3_EMC3080P",
                            },
                        }
                        response = coap_reply(token, payload)
                    else:
                        body = b"\x23" + socket.inet_aton("127.0.0.1") + MAC
                        response = b"\xa1\x06" + MAC + b"\x12\x00" + packet[10:12]
                        response += b"\xf1\x02\x12\x34" + body
                    server.sendto(response, peer)
                except Exception as exc:
                    failures.append(exc)

        threads = [
            threading.Thread(target=serve, args=(s, b), daemon=True)
            for s, b in ((coap, True), (legacy, False))
        ]
        for thread in threads:
            thread.start()
        clients = []

        class Client:
            def __init__(self, *a):
                self.real = REAL_SOCKET(*a)
                self.closed = False
                clients.append(self)

            def __getattr__(self, name):
                return getattr(self.real, name)

            def bind(self, peer):
                if peer[1] == 11530:
                    raise OSError(errno.EADDRINUSE, "fixture")
                return self.real.bind(peer)

            def sendto(self, packet, peer):
                port = {5683: coap_port, 11530: legacy_port}.get(peer[1], peer[1])
                return self.real.sendto(packet, ("127.0.0.1", port))

            def close(self):
                self.closed = True
                self.real.close()

        target = args(seconds=0.3)
        target.target = "127.0.0.1"
        try:
            with (
                patch.object(probe.socket, "socket", Client),
                patch.object(
                    probe,
                    "route_and_broadcast",
                    return_value=("127.0.0.1", "127.255.255.255", "fixture"),
                ),
            ):
                report = probe.run(target)
        finally:
            stop.set()
            for thread in threads:
                thread.join(1)
            coap.close()
            legacy.close()
        self.assertEqual(failures, [])
        self.assertTrue(all(c.closed for c in clients))
        self.assertEqual(report["status"], "complete")
        self.assertGreaterEqual(report["receive"]["target"], 8)
        self.assertEqual(len(report["target_response_counts"]), 8)
        text = json.dumps(report)
        for secret in (PRIVATE, "127.0.0.1", "12:34:56:78:9a:bc"):
            self.assertNotIn(secret, text)
        self.assertIn(PK, text)
        self.assertIn("1.6.3_EMC3080P", text)


class ExtendedTests(unittest.TestCase):
    def test_arp_uses_only_complete_exact_target(self):
        data = "IP address HW type Flags HW address Mask Device\n"
        data += "192.0.2.1 0x1 0x2 12:34:56:78:9a:bc * eth0\n"
        data += "192.0.2.123 0x1 0x0 12:34:56:78:9a:bc * eth0\n"
        with patch("builtins.open", mock_open(read_data=data)):
            self.assertIsNone(probe.neighbor_mac("192.0.2.123"))
        data += "192.0.2.123 0x1 0x2 22:34:56:78:9a:bc * eth0\n"
        with patch("builtins.open", mock_open(read_data=data)):
            self.assertEqual(
                probe.neighbor_mac("192.0.2.123"), bytes.fromhex("223456789abc")
            )

    def test_empty_coap_ack_and_reset_are_mid_correlated(self):
        requests = {TOKEN: {"mid": 42, "name": "info_unicast_con", "id": "7"}}
        for header, kind in ((0x60, "ACK"), (0x70, "RST")):
            detail, reply = probe.read_coap(bytes((header, 0, 0, 42)), requests)
            self.assertTrue(detail["message_id_matches_request"])
            self.assertFalse(detail["token_matches_request"])
            self.assertEqual(detail["probe"], "info_unicast_con")
            self.assertEqual(detail["type"], kind)
            self.assertIsNone(reply)

    def test_capture_sanitizes_sll_sll2_and_limits_histograms(self):
        capture = probe.HeaderCapture("192.0.2.123")
        capture.observe(
            "12.5 eth0 Out IP 192.0.2.1.11530 > 192.0.2.123.11530: UDP, length 17"
        )
        capture.observe("12.6 IP 192.0.2.123.11530 > 192.0.2.1.11530: UDP, length 49")
        capture.observe(
            "12.6 ovs_eth0 In IP 192.0.2.123.11530 > 192.0.2.1.11530: UDP, length 49"
        )
        for port in range(1000, 1100):
            capture.observe(
                f"12.7 IP 192.0.2.123.{port} > 192.0.2.1.11530: UDP, length {port}"
            )
        self.assertEqual(capture.result["target_incoming_observations"], 102)
        self.assertEqual(capture.result["target_outgoing_observations"], 1)
        self.assertLessEqual(len(capture.result["incoming_source_ports"]), 33)
        self.assertNotIn("192.0.2.", json.dumps(capture.result))

    def test_failed_channel_does_not_prevent_other_channel(self):
        class Sock:
            closed = False

            def setsockopt(self, level, option, value):
                if option == socket.IP_MULTICAST_IF:
                    raise OSError(errno.EPERM, PRIVATE)

            def bind(self, peer):
                pass

            def setblocking(self, value):
                pass

            def close(self):
                self.closed = True

        report = {}
        coap, legacy = Sock(), Sock()
        with patch.object(probe.socket, "socket", side_effect=[coap, legacy]):
            self.assertIsNone(probe.open_channel("coap", "192.0.2.1", report))
            self.assertIs(probe.open_channel("legacy", "192.0.2.1", report), legacy)
        self.assertTrue(coap.closed)
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_optional_control_gets_own_identity_and_report(self):
        sample = {"status": "complete", "power_test": {"status": "skipped"}}
        seen = []

        def run(a):
            seen.append((a.target, a.label, a.mac))
            return sample.copy()

        with (
            patch.object(
                probe.sys,
                "argv",
                ["probe", "192.0.2.123", "192.0.2.124", "--mac", "12:34:56:78:9a:bc"],
            ),
            patch.object(probe, "run", side_effect=run),
            patch("sys.stdout", new_callable=io.StringIO) as output,
        ):
            self.assertEqual(probe.main(), 0)
        self.assertEqual(
            seen, [("192.0.2.123", "plus", MAC), ("192.0.2.124", "x83c", None)]
        )
        self.assertEqual(len(json.loads(output.getvalue())["devices"]), 2)


class LauncherTests(unittest.TestCase):
    def launch(self, host="old", docker="one", network="host"):
        launcher = SCRIPT.with_suffix(".sh")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / "python3"
            python.write_text(r"""#!/bin/sh
if [ "$MOCK_HOST" = old ]; then exit 1; fi
if [ "$MOCK_HOST" = incomplete ] && [ "$1" != -c ]; then exit 1; fi
if [ "$1" = -c ]; then exit 0; fi
printf '%s\n' '{"status":"host_runtime_ok"}'
""")
            python.chmod(0o755)
            docker_file = root / "docker"
            docker_file.write_text(r"""#!/bin/sh
case "$1" in
ps)
  [ "$MOCK_DOCKER" = denied ] && exit 1
  printf '%s\n' aabbcc
  [ "$MOCK_DOCKER" = two ] && printf '%s\n' ddeeff
  exit 0 ;;
inspect)
  case "$3" in
    *Config.Image*) printf '%s\n' ghcr.io/home-assistant/home-assistant:stable ;;
    *) printf '%s\n' "$MOCK_NETWORK" ;;
  esac ;;
exec)
  case "$*" in
    *PROBE_RUNTIME*)
      cat >/dev/null; printf '%s\n' '{"status":"container_runtime_ok"}' ;;
    *--check-runtime*) cat >/dev/null; exit 0 ;;
    *) exit 0 ;;
  esac ;;
esac
""")
            docker_file.chmod(0o755)
            env = dict(
                os.environ,
                PATH=str(root) + ":/usr/bin:/bin",
                MOCK_HOST=host,
                MOCK_DOCKER=docker,
                MOCK_NETWORK=network,
                MOCK_BIN=str(root),
            )
            harness = (
                'command() { case "$2" in python3|docker) test -x "$MOCK_BIN/$2" ;; '
                '*) return 1 ;; esac; }; . "$0"'
            )
            result = subprocess.run(
                ["/bin/sh", "-c", harness, str(launcher), "--check-runtime"],
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode, json.loads(result.stdout)

    def test_host_python_is_preferred(self):
        code, result = self.launch(host="ok")
        self.assertEqual((code, result["status"]), (0, "host_runtime_ok"))

    def test_old_or_incomplete_host_falls_back_to_verified_container(self):
        for host in ("old", "incomplete"):
            code, result = self.launch(host=host)
            self.assertEqual((code, result["status"]), (0, "container_runtime_ok"))

    def test_denied_docker_bridge_and_ambiguous_containers_return_report(self):
        for docker, network in (("denied", "host"), ("one", "bridge"), ("two", "host")):
            code, result = self.launch(docker=docker, network=network)
            self.assertEqual(code, 1)
            self.assertEqual(result["status"], "runtime_unavailable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
