#!/usr/bin/env python3
# Copyright (C) 2026 jack16683
# SPDX-License-Identifier: GPL-3.0-or-later
"""Local recurring-schedule manager for 352 air purifiers.

This is a standalone standard-library tool.  It talks only to a selected LAN
device over UDP port 11530 and never contacts the retired 352 cloud service.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable


UDP_PORT = 11530
DISCOVERY_AUTH = 0xCB76
VENDOR_OUI = "009569"
SCHEDULE_FAMILIES = {2, 3, 4}
PASSIVE_TIMEOUT = 45.0
ACTIVE_SCAN_ROUNDS = 2
ACTIVE_SCAN_WAIT = 3.0
NEIGHBOR_SCAN_WAIT = 3.0
NEIGHBOR_SETTLE_TIME = 1.0
DARWIN_NEIGHBOR_SCAN_WAIT = 1.0

FAMILY_NAMES = {
    1: "M25（检测仪，不支持净化器定时）",
    2: "X83 / X83C / X83C Plus",
    3: "X50 / X50S / X60 / X70（实验性）",
    4: "G30 / G45（实验性）",
}
FAMILY_NAMES_EN = {
    1: "M25 (monitor; purifier schedules unsupported)",
    2: "X83 / X83C / X83C Plus",
    3: "X50 / X50S / X60 / X70 (experimental)",
    4: "G30 / G45 (experimental)",
}

MODEL_PROFILES = {
    "x83c": (2, 0x0403),
    "x83": (2, 0x0504),
    "x83c-plus": (2, 0x0504),
    "x50": (3, 0x0504),
    "x50s": (3, 0x0504),
    "x60": (3, 0x0504),
    "x70": (3, 0x0504),
    "g30": (4, 0x0504),
    "g45": (4, 0x0504),
}

DAY_BITS = {
    "sun": 0,
    "sunday": 0,
    "日": 0,
    "周日": 0,
    "星期日": 0,
    "mon": 1,
    "monday": 1,
    "一": 1,
    "周一": 1,
    "星期一": 1,
    "tue": 2,
    "tuesday": 2,
    "二": 2,
    "周二": 2,
    "星期二": 2,
    "wed": 3,
    "wednesday": 3,
    "三": 3,
    "周三": 3,
    "星期三": 3,
    "thu": 4,
    "thursday": 4,
    "四": 4,
    "周四": 4,
    "星期四": 4,
    "fri": 5,
    "friday": 5,
    "五": 5,
    "周五": 5,
    "星期五": 5,
    "sat": 6,
    "saturday": 6,
    "六": 6,
    "周六": 6,
    "星期六": 6,
}
DAY_LABELS = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]
DAY_LABELS_EN = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
LANGUAGE = "zh"

MAC_RE = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}(?![0-9a-f])"
)
IP_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")


class ScheduleError(RuntimeError):
    """A safe, user-facing protocol or validation failure."""


def ui(chinese: str, english: str) -> str:
    return chinese if LANGUAGE == "zh" else english


def display_width(value: str) -> int:
    """Return the number of terminal columns used by a plain text value."""
    return sum(
        0
        if unicodedata.combining(character)
        else 2
        if unicodedata.east_asian_width(character) in {"W", "F"}
        else 1
        for character in value
    )


def pad_display(value: object, width: int) -> str:
    text = str(value)
    return text + " " * max(0, width - display_width(text))


def format_row(values: Iterable[object], widths: Iterable[int]) -> str:
    return "  ".join(
        pad_display(value, width) for value, width in zip(values, widths)
    ).rstrip()


def choose_language() -> None:
    global LANGUAGE
    try:
        answer = input("语言 / Language（回车中文，2=English）：").strip().lower()
    except EOFError:
        answer = ""
    LANGUAGE = "en" if answer in {"2", "e", "en", "eng", "english"} else "zh"


def normalize_mac(value: str) -> str:
    parts = re.split(r"[:-]", value.strip())
    if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", part) for part in parts):
        compact = "".join(part.zfill(2) for part in parts).upper()
    else:
        compact = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(compact) != 12:
        raise ScheduleError(
            ui(
                "MAC 地址必须包含 12 个十六进制字符",
                "MAC address must contain 12 hexadecimal characters",
            )
        )
    try:
        bytes.fromhex(compact)
    except ValueError as exc:
        raise ScheduleError(ui("MAC 地址格式无效", "Invalid MAC address")) from exc
    return compact


def display_mac(value: str) -> str:
    value = normalize_mac(value)
    return ":".join(value[index : index + 2] for index in range(0, 12, 2))


def parse_hex_u16(value: str) -> int:
    text = value.strip().lower()
    base = 16 if not text.startswith("0x") else 0
    parsed = int(text, base)
    if not 0 <= parsed <= 0xFFFF:
        raise argparse.ArgumentTypeError("值必须在 0000 到 FFFF 之间")
    return parsed


def parse_hex_u8(value: str) -> int:
    parsed = parse_hex_u16(value)
    if parsed > 0xFF:
        raise argparse.ArgumentTypeError("值必须在 00 到 FF 之间")
    return parsed


def crc16_genibus(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF
                if crc & 0x8000
                else (crc << 1) & 0xFFFF
            )
    return crc ^ 0xFFFF


def bcd_encode(value: int) -> int:
    return ((value // 10) << 4) | (value % 10)


def bcd_decode(value: int) -> int:
    high, low = value >> 4, value & 0x0F
    if high > 9 or low > 9:
        raise ScheduleError(
            ui(
                f"设备返回了无效 BCD 值 0x{value:02X}",
                f"Device returned invalid BCD value 0x{value:02X}",
            )
        )
    return high * 10 + low


def parse_time(value: str | None) -> tuple[int, int] | None:
    if value is None or value.strip() in {"", "-", "none", "无"}:
        return None
    text = value.strip()
    compact_match = re.fullmatch(r"\d{3,4}", text)
    if compact_match:
        compact = text.zfill(4)
        match = re.fullmatch(r"(\d{2})(\d{2})", compact)
    else:
        match = re.fullmatch(r"(\d{1,2}):(\d{2})", text)
    if not match:
        raise ScheduleError(
            ui(
                f"时间 {value!r} 必须使用 1700 或 17:00 格式",
                f"Time {value!r} must use 1700 or 17:00 format",
            )
        )
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        raise ScheduleError(
            ui(
                f"时间 {value!r} 超出有效范围",
                f"Time {value!r} is outside the valid range",
            )
        )
    return hour, minute


def encode_time(value: str | None) -> bytes:
    parsed = parse_time(value)
    if parsed is None:
        return b"\xFF\xFF"
    return bytes((bcd_encode(parsed[0]), bcd_encode(parsed[1])))


def decode_time(hour: int, minute: int) -> str | None:
    if hour == 0xFF or minute == 0xFF:
        return None
    decoded_hour, decoded_minute = bcd_decode(hour), bcd_decode(minute)
    if decoded_hour > 23 or decoded_minute > 59:
        raise ScheduleError(
            ui(
                "设备返回了超出范围的定时时间",
                "Device returned an out-of-range schedule time",
            )
        )
    return f"{decoded_hour:02d}:{decoded_minute:02d}"


def parse_days(value: str) -> int:
    normalized = value.strip().lower()
    if normalized in {
        "all",
        "daily",
        "everyday",
        "每天",
        "全部",
        "1234567",
        "1-7",
        "1到7",
    }:
        return 0x7F
    mask = 0
    if re.fullmatch(r"[1-7]+", normalized):
        numeric_days = list(normalized)
    elif re.fullmatch(r"[1-7](?:[,，\s]+[1-7])+", normalized):
        numeric_days = [part for part in re.split(r"[,，\s]+", normalized) if part]
    else:
        numeric_days = []
    if numeric_days:
        for day in numeric_days:
            number = int(day)
            bit = 0 if number == 7 else number
            mask |= 1 << bit
        return mask
    tokens = [
        part.strip().lower()
        for part in re.split(r"[,，\s]+", value)
        if part.strip()
    ]
    if not tokens:
        raise ScheduleError(
            ui(
                "至少选择一天；1=周一，7=周日，每天可写 all",
                "Select at least one day; 1=Monday, 7=Sunday, or use all",
            )
        )
    for token in tokens:
        if token not in DAY_BITS:
            raise ScheduleError(
                ui(
                    f"无法识别星期 {token!r}",
                    f"Unrecognized day value {token!r}",
                )
            )
        mask |= 1 << DAY_BITS[token]
    return mask


@dataclass(frozen=True)
class ScheduleSlot:
    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 8:
            raise ValueError("schedule slot must contain eight bytes")

    @property
    def empty(self) -> bool:
        return (
            all(value == 0 for value in self.raw[:6])
            or self.raw[1:5] == b"\xFF" * 4
        )

    @property
    def enabled(self) -> bool:
        return not self.empty and bool(self.raw[0] & 0x80)

    @property
    def days_mask(self) -> int:
        return self.raw[0] & 0x7F

    @property
    def turn_on(self) -> str | None:
        return None if self.empty else decode_time(self.raw[1], self.raw[2])

    @property
    def turn_off(self) -> str | None:
        return None if self.empty else decode_time(self.raw[3], self.raw[4])

    @property
    def day_labels(self) -> list[str]:
        return [
            label
            for bit, label in enumerate(DAY_LABELS)
            if self.days_mask & (1 << bit)
        ]

    def with_enabled(self, enabled: bool) -> "ScheduleSlot":
        if self.empty:
            raise ScheduleError(
                ui(
                    "空定时槽不能直接启用，请先设置时间",
                    "An empty slot cannot be enabled; set its time first",
                )
            )
        first = (self.raw[0] & 0x7F) | (0x80 if enabled else 0)
        return ScheduleSlot(bytes((first,)) + self.raw[1:])

    @classmethod
    def configured(
        cls,
        turn_on: str | None,
        turn_off: str | None,
        days_mask: int,
        enabled: bool,
    ) -> "ScheduleSlot":
        if parse_time(turn_on) is None and parse_time(turn_off) is None:
            raise ScheduleError(
                ui(
                    "开机和关机时间不能同时为空",
                    "Turn-on and turn-off times cannot both be empty",
                )
            )
        flag = days_mask | (0x80 if enabled else 0)
        return cls(
            bytes((flag,))
            + encode_time(turn_on)
            + encode_time(turn_off)
            + b"\x00\x00\x00"
        )

    @classmethod
    def blank(cls) -> "ScheduleSlot":
        return cls(b"\x00\xFF\xFF\xFF\xFF\x00\x00\x00")

    def as_dict(self, slot: int) -> dict[str, object]:
        return {
            "slot": slot,
            "configured": not self.empty,
            "enabled": self.enabled,
            "days": self.day_labels,
            "turn_on": self.turn_on,
            "turn_off": self.turn_off,
        }


@dataclass
class Device:
    host: str
    mac: str
    family: int
    company: int
    auth: int
    sequence: int = 0

    @property
    def family_name(self) -> str:
        if LANGUAGE == "en":
            return FAMILY_NAMES_EN.get(self.family, f"Unknown family {self.family}")
        return FAMILY_NAMES.get(self.family, f"未知协议族 {self.family}")


def wrap_packet(device: Device, sequence: int, inner: bytes) -> bytes:
    payload = b"\x01" + inner
    return (
        b"\xA1\x04"
        + bytes.fromhex(device.mac)
        + bytes((len(payload) + 7, 0))
        + sequence.to_bytes(2, "big")
        + bytes((device.company, device.family))
        + device.auth.to_bytes(2, "big")
        + payload
    )


def discovery_packet(mac: str, family: int, sequence: int) -> bytes:
    return (
        b"\xA1\x04"
        + bytes.fromhex(mac)
        + b"\x08\x00"
        + sequence.to_bytes(2, "big")
        + bytes((0xF1, family))
        + DISCOVERY_AUTH.to_bytes(2, "big")
        + b"\x23"
    )


def schedule_query_packet(device: Device, sequence: int) -> bytes:
    inner = bytearray(14)
    inner[0:4] = b"\xF0\x72\x00\x0C"
    inner[4:7] = bytes((device.family, 0x04, 0x0C))
    inner[7:9] = sequence.to_bytes(2, "big")
    inner[9:12] = b"\x01\x04\x04"
    inner[12:14] = crc16_genibus(bytes(inner[2:12])).to_bytes(2, "big")
    return wrap_packet(device, sequence, bytes(inner))


def schedule_write_packet(
    device: Device, sequence: int, slots: Iterable[ScheduleSlot]
) -> bytes:
    slots = list(slots)
    if len(slots) != 4:
        raise ValueError("exactly four schedule slots are required")
    body = b"\x04\x20" + b"".join(slot.raw for slot in slots)
    inner = bytearray(47)
    inner[0:4] = b"\xF0\x72\x00\x2D"
    inner[4:7] = bytes((device.family, 0x04, 0x0B))
    inner[7:9] = sequence.to_bytes(2, "big")
    inner[9] = len(body)
    inner[10:44] = body
    inner[44] = sum(body) & 0xFF
    inner[45:47] = crc16_genibus(bytes(inner[2:45])).to_bytes(2, "big")
    return wrap_packet(device, sequence, bytes(inner))


def parse_discovery_response(data: bytes, address: tuple[str, int]) -> Device | None:
    if (
        len(data) < 27
        or data[0:2] != b"\xA1\x06"
        or data[16] != 0x23
        or data[2:8] != data[21:27]
        or data[13] not in FAMILY_NAMES
    ):
        return None
    advertised = str(ipaddress.ip_address(data[17:21]))
    host = address[0] if advertised == "0.0.0.0" else advertised
    return Device(
        host=host,
        mac=data[2:8].hex().upper(),
        family=data[13],
        company=data[12],
        auth=int.from_bytes(data[14:16], "big"),
        sequence=int.from_bytes(data[10:12], "big"),
    )


def parse_passive_device(data: bytes, address: tuple[str, int]) -> Device | None:
    if (
        len(data) < 16
        or data[0] != 0xA1
        or data[13] not in FAMILY_NAMES
        or address[1] != UDP_PORT
    ):
        return None
    mac = data[2:8].hex().upper()
    if not mac.startswith(VENDOR_OUI):
        return None
    return Device(
        host=address[0],
        mac=mac,
        family=data[13],
        company=data[12],
        auth=int.from_bytes(data[14:16], "big"),
        sequence=int.from_bytes(data[10:12], "big"),
    )


def parse_schedule_response(
    data: bytes, address: tuple[str, int], device: Device
) -> list[ScheduleSlot] | None:
    if (
        address[0] != device.host
        or len(data) < 61
        or data[0] != 0xA1
        or data[2:8] != bytes.fromhex(device.mac)
        or data[13] != device.family
        or data[16] != 0x02
    ):
        return None
    inner = data[17:]
    if len(inner) < 14 or inner[0:2] != b"\xF0\x72":
        return None
    declared_length = int.from_bytes(inner[2:4], "big") + 2
    if declared_length > len(inner) or declared_length < 47:
        return None
    inner = inner[:declared_length]
    if (
        inner[4] != device.family
        or inner[5] not in {0x84, 0x03}
        or inner[6] != 0x0C
        or inner[10:12] != b"\x04\x20"
    ):
        return None
    expected_crc = int.from_bytes(inner[-2:], "big")
    if crc16_genibus(inner[2:-2]) != expected_crc:
        raise ScheduleError(
            ui(
                "定时查询响应的 CRC 校验失败",
                "Schedule response CRC validation failed",
            )
        )
    return [
        ScheduleSlot(bytes(inner[12 + index * 8 : 20 + index * 8]))
        for index in range(4)
    ]


class LanClient:
    def __init__(self, timeout: float = 2.5) -> None:
        self.timeout = timeout
        self.sequence = int(time.monotonic_ns() // 1_000_000) & 0xFFFF
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Replies always return to UDP 11530. Allowing multiple listeners makes
        # the OS distribute packets between them and causes intermittent misses.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            self.socket.bind(("", UDP_PORT))
        except OSError as exc:
            self.socket.close()
            raise ScheduleError(
                ui(
                    f"无法监听 UDP {UDP_PORT}：{exc}。请关闭占用端口的程序后重试",
                    f"Could not bind UDP {UDP_PORT}: {exc}. Close the program using the port and retry",
                )
            ) from exc
        self.socket.settimeout(0.2)

    def __enter__(self) -> "LanClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.socket.close()

    def next_sequence(self) -> int:
        self.sequence = (self.sequence + 1) & 0xFFFF
        return self.sequence

    def learn_sequence(self, sequence: int) -> None:
        if sequence:
            self.sequence = sequence

    def send(self, packet: bytes, host: str) -> None:
        self.socket.sendto(packet, (host, UDP_PORT))

    def drain(self) -> None:
        self.socket.setblocking(False)
        try:
            while True:
                self.socket.recvfrom(4096)
        except BlockingIOError:
            pass
        finally:
            self.socket.setblocking(True)
            self.socket.settimeout(0.2)

    def wait_for(
        self,
        parser: Callable[[bytes, tuple[str, int]], object | None],
        timeout: float,
    ) -> object | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, address = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            parsed = parser(data, address)
            if parsed is not None:
                return parsed
        return None

    def discover(
        self, host: str, mac: str, family_hint: int | None = None
    ) -> Device | None:
        mac = normalize_mac(mac)
        families = [family_hint] if family_hint else [1, 2, 3, 4]
        self.drain()
        for family in families:
            sequence = self.next_sequence()
            self.send(discovery_packet(mac, family, sequence), host)
        result = self.wait_for(
            lambda data, address: (
                parsed
                if (parsed := parse_discovery_response(data, address))
                and parsed.mac == mac
                and parsed.host == host
                else None
            ),
            self.timeout,
        )
        if isinstance(result, Device):
            self.learn_sequence(result.sequence)
            return result
        return None

    def query(self, device: Device, attempts: int = 3) -> list[ScheduleSlot]:
        if device.family not in SCHEDULE_FAMILIES:
            raise ScheduleError(
                ui(
                    f"{device.family_name} 没有净化器定时协议",
                    f"{device.family_name} has no purifier schedule protocol",
                )
            )
        for _ in range(attempts):
            self.drain()
            sequence = self.next_sequence()
            self.send(schedule_query_packet(device, sequence), device.host)
            result = self.wait_for(
                lambda data, address: parse_schedule_response(data, address, device),
                self.timeout,
            )
            if isinstance(result, list):
                return result
        raise ScheduleError(
            ui(
                "设备没有回复定时查询；请确认电脑与净化器在可传递 UDP 的同一局域网",
                "The device did not answer the schedule query; verify bidirectional UDP connectivity",
            )
        )

    def write_once(self, device: Device, slots: list[ScheduleSlot]) -> None:
        self.drain()
        sequence = self.next_sequence()
        self.send(schedule_write_packet(device, sequence, slots), device.host)

    def collect_devices(self, seconds: float) -> list[Device]:
        devices: dict[str, Device] = {}
        deadline = time.monotonic() + seconds
        last_new_device: float | None = None
        while time.monotonic() < deadline:
            if last_new_device is not None and time.monotonic() - last_new_device >= 1.0:
                break
            try:
                data, address = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            parsed = parse_discovery_response(data, address) or parse_passive_device(
                data, address
            )
            if parsed is not None:
                if parsed.mac not in devices:
                    last_new_device = time.monotonic()
                devices[parsed.mac] = parsed
        return sorted(devices.values(), key=lambda item: (item.host, item.mac))

    def wait_for_host_broadcast(self, host: str, seconds: float) -> Device | None:
        """Learn a device from its periodic status packet without ARP."""
        result = self.wait_for(
            lambda data, address: (
                parsed
                if (parsed := parse_passive_device(data, address))
                and parsed.host == host
                else None
            ),
            seconds,
        )
        if isinstance(result, Device):
            self.learn_sequence(result.sequence)
            return result
        return None


def run_neighbor_command() -> str:
    system = platform.system()
    if system == "Windows":
        commands: tuple[list[str], ...] = (["arp", "-a"],)
    elif system == "Darwin":
        # GUI launchers and restricted Python environments may have a minimal
        # PATH even though the system ARP command is available here.
        commands = (["/usr/sbin/arp", "-n", "-a"], ["arp", "-n", "-a"])
    else:
        commands = (
            ["ip", "neigh", "show"],
            ["/usr/sbin/arp", "-n", "-a"],
            ["arp", "-n", "-a"],
        )
    outputs: list[str] = []
    if platform.system() == "Linux":
        try:
            with open("/proc/net/arp", encoding="utf-8") as arp_table:
                outputs.append(arp_table.read())
        except OSError:
            pass
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        outputs.append(result.stdout)
    return "\n".join(outputs)


def parse_neighbor_entries(output: str) -> list[tuple[str, str]]:
    """Parse macOS, Linux and Windows ARP/neighbor command output."""
    entries: dict[str, str] = {}
    for line in output.splitlines():
        mac_match = MAC_RE.search(line)
        ip_match = IP_RE.search(line)
        if not mac_match or not ip_match:
            continue
        try:
            ipaddress.ip_address(ip_match.group())
            mac = normalize_mac(mac_match.group())
        except (ValueError, ScheduleError):
            continue
        entries[ip_match.group()] = mac
    return sorted(entries.items())


def neighbor_entries() -> list[tuple[str, str]]:
    return parse_neighbor_entries(run_neighbor_command())


def warm_neighbor(host: str) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.1)
            probe.sendto(b"", (host, 9))
    except OSError:
        pass
    time.sleep(0.2)


def resolve_neighbor_mac(host: str) -> str | None:
    ipaddress.ip_address(host)
    warm_neighbor(host)
    return dict(neighbor_entries()).get(host)


def infer_local_subnet() -> ipaddress.IPv4Network | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            address = probe.getsockname()[0]
        return ipaddress.ip_network(f"{address}/24", strict=False)
    except OSError:
        return None


def warm_darwin_neighbor(host: str) -> None:
    """Make macOS complete neighbor resolution instead of queueing a UDP burst."""
    try:
        subprocess.run(
            ["/sbin/ping", "-n", "-q", "-c", "1", "-W", "200", host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def warm_subnet(network: ipaddress.IPv4Network) -> bool:
    """Trigger neighbor discovery and report whether all probes completed."""
    hosts = list(network.hosts())
    if len(hosts) > 1024:
        raise ScheduleError(
            "为避免扫描过大网络，请使用不超过 1024 个地址的网段"
        )
    if platform.system() == "Darwin":
        with ThreadPoolExecutor(max_workers=min(64, len(hosts))) as executor:
            tuple(executor.map(warm_darwin_neighbor, map(str, hosts)))
        return True

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.setblocking(False)
        for host in hosts:
            try:
                probe.sendto(b"", (str(host), 9))
            except OSError:
                continue
    return False


def wait_for_vendor_neighbors(
    timeout: float, settle_time: float = NEIGHBOR_SETTLE_TIME
) -> list[tuple[str, str]]:
    """Wait for the ARP/neighbor sweep instead of assuming a fixed delay."""
    deadline = time.monotonic() + max(0.0, timeout)
    candidates: list[tuple[str, str]] = []
    last_change: float | None = None
    while True:
        current = [
            (host, mac)
            for host, mac in neighbor_entries()
            if mac.startswith(VENDOR_OUI)
        ]
        now = time.monotonic()
        if current != candidates:
            candidates = current
            last_change = now
        if candidates and last_change is not None:
            if now - last_change >= settle_time:
                return candidates
        remaining = deadline - now
        if remaining <= 0:
            return candidates
        time.sleep(min(0.2, remaining))


def scan_devices(client: LanClient, subnet: str | None, timeout: float) -> list[Device]:
    client.drain()
    deadline = time.monotonic() + timeout
    network = (
        ipaddress.ip_network(subnet, strict=False)
        if subnet
        else infer_local_subnet()
    )
    if network is not None:
        if not isinstance(network, ipaddress.IPv4Network):
            raise ScheduleError(
                ui(
                    "目前只支持 IPv4 局域网扫描",
                    "Only IPv4 LAN scanning is currently supported",
                )
            )
        print(
            ui(
                f"正在扫描 {network} 的 352 设备……",
                f"Scanning {network} for 352 devices...",
            ),
            file=sys.stderr,
        )
    else:
        print(
            ui(
                "无法自动判断本地网段，将使用邻居缓存和被动监听。",
                "Could not infer the local subnet; using neighbor cache and passive listening.",
            ),
            file=sys.stderr,
        )

    found: dict[str, Device] = {}
    attempted_candidates: set[tuple[str, str]] = set()
    request_count = 0
    for round_number in range(1, ACTIVE_SCAN_ROUNDS + 1):
        candidates = wait_for_vendor_neighbors(0, settle_time=0.0)
        if network is not None and not candidates:
            completed = warm_subnet(network)
            neighbor_wait = (
                DARWIN_NEIGHBOR_SCAN_WAIT if completed else NEIGHBOR_SCAN_WAIT
            )
            candidates = wait_for_vendor_neighbors(
                min(neighbor_wait, max(0.0, deadline - time.monotonic())),
                settle_time=0.0 if completed else NEIGHBOR_SETTLE_TIME,
            )
        attempted_candidates.update(candidates)
        for host, mac in candidates:
            for family in (1, 2, 3, 4):
                sequence = client.next_sequence()
                client.send(discovery_packet(mac, family, sequence), host)
                request_count += 1
        print(
            ui(
                f"主动发现第 {round_number}/{ACTIVE_SCAN_ROUNDS} 轮："
                f"找到 {len(candidates)} 个候选，发送 {len(candidates) * 4} 个请求。",
                f"Active discovery round {round_number}/{ACTIVE_SCAN_ROUNDS}: "
                f"{len(candidates)} candidate(s), {len(candidates) * 4} request(s) sent.",
            ),
            file=sys.stderr,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        for device in client.collect_devices(min(ACTIVE_SCAN_WAIT, remaining)):
            found[device.mac] = device
        if found:
            return sorted(found.values(), key=lambda item: (item.host, item.mac))

    remaining = deadline - time.monotonic()
    if remaining > 0:
        if request_count:
            reason_zh = (
                f"已向 {len(attempted_candidates)} 个候选发送 {request_count} 个发现请求，"
                "但尚未收到发现响应"
            )
            reason_en = (
                f"Sent {request_count} discovery request(s) to "
                f"{len(attempted_candidates)} candidate(s), but received no discovery response"
            )
        else:
            reason_zh = "邻居表中没有找到 352 厂商 MAC，未发送定向发现请求"
            reason_en = (
                "No 352 vendor MAC was found in the neighbor table; "
                "no directed discovery request was sent"
            )
        print(
            ui(
                f"{reason_zh}；继续监听状态广播（最多 {remaining:.0f} 秒）……",
                f"{reason_en}; listening for status broadcasts (up to {remaining:.0f}s)...",
            ),
            file=sys.stderr,
        )
        for device in client.collect_devices(remaining):
            found[device.mac] = device
    return sorted(found.values(), key=lambda item: (item.host, item.mac))


def fallback_device(
    host: str,
    mac: str,
    model: str,
    company: int | None,
    auth: int | None,
) -> Device:
    family, default_auth = MODEL_PROFILES[model]
    return Device(
        host=host,
        mac=normalize_mac(mac),
        family=family,
        company=0xF1 if company is None else company,
        auth=default_auth if auth is None else auth,
    )


def connect_device(client: LanClient, args: argparse.Namespace) -> Device:
    host = str(ipaddress.ip_address(args.host))
    mac = normalize_mac(args.mac) if args.mac else resolve_neighbor_mac(host)
    if mac is None:
        print(
            ui(
                f"邻居表没有 MAC，正在监听设备状态广播，最多 {args.passive_timeout:g} 秒……",
                f"No MAC in the neighbor table; listening for status broadcasts for up to {args.passive_timeout:g} seconds...",
            ),
            file=sys.stderr,
        )
        passive = client.wait_for_host_broadcast(host, args.passive_timeout)
        if passive is not None:
            return passive
        raise ScheduleError(
            ui(
                "无法自动取得 MAC；跨网段使用时请同时提供 --mac",
                "Could not learn the MAC automatically; provide --mac across routed networks",
            )
        )
    family_hint = MODEL_PROFILES[args.model][0] if args.model else None
    discovered = client.discover(host, mac, family_hint)
    if discovered is not None:
        return discovered
    if args.model is None:
        raise ScheduleError(
            ui(
                "设备未回复发现请求；请提供 --model 和必要时的 --auth 作为手动参数",
                "Discovery did not respond; provide --model and, if needed, --auth",
            )
        )
    print(
        ui(
            "警告：设备未回复发现请求，正在使用手动型号的鉴权默认值。",
            "Warning: discovery did not respond; using the selected model's default authentication value.",
        ),
        file=sys.stderr,
    )
    return fallback_device(host, mac, args.model, args.company, args.auth)


def print_devices(devices: list[Device], as_json: bool = False) -> None:
    if as_json:
        print(
            json.dumps(
                [
                    {
                        "host": device.host,
                        "mac": display_mac(device.mac),
                        "family": device.family,
                        "family_name": device.family_name,
                    }
                    for device in devices
                ],
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if not devices:
        print(
            ui(
                "没有发现 352 设备。可改用手动 IP，并在跨网段时同时填写 MAC。",
                "No 352 devices found. Try a manual IP and provide the MAC across routed networks.",
            )
        )
        return
    for index, device in enumerate(devices, 1):
        print(
            f"{index}. {device.host:<15} "
            f"{display_mac(device.mac)}  {device.family_name}"
        )


def print_schedule(slots: list[ScheduleSlot], as_json: bool = False) -> None:
    if as_json:
        print(
            json.dumps(
                [slot.as_dict(index) for index, slot in enumerate(slots, 1)],
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    headers = (
        ("Slot", "Status", "Days", "On", "Off")
        if LANGUAGE == "en"
        else ("槽", "状态", "星期", "开机", "关机")
    )
    widths = (4, 8, 27 if LANGUAGE == "en" else 35, 6, 6)
    print(format_row(headers, widths))
    print("  ".join("-" * width for width in widths))
    for index, slot in enumerate(slots, 1):
        if slot.empty:
            empty = "Empty" if LANGUAGE == "en" else "空"
            values = (index, empty, "", "", "")
            print(format_row(values, widths))
            continue
        labels = DAY_LABELS_EN if LANGUAGE == "en" else DAY_LABELS
        selected_days = [
            label
            for bit, label in enumerate(labels)
            if slot.days_mask & (1 << bit)
        ]
        if LANGUAGE == "en":
            days = "Daily" if slot.days_mask == 0x7F else ",".join(selected_days) or "None"
            status = "Enabled" if slot.enabled else "Disabled"
        else:
            days = "每天" if slot.days_mask == 0x7F else "、".join(selected_days) or "未选择"
            status = "启用" if slot.enabled else "停用"
        values = (index, status, days, slot.turn_on or "--", slot.turn_off or "--")
        print(format_row(values, widths))


def require_clear_confirmation(args: argparse.Namespace) -> None:
    if getattr(args, "yes", False):
        return
    if not sys.stdin.isatty():
        raise ScheduleError(
            ui(
                "清除全部定时需要 --yes；本次没有发送任何写入包",
                "Clearing all schedules requires --yes; no write packet was sent",
            )
        )
    answer = input(
        ui(
            "将清除设备内全部 4 个循环定时槽。\n输入 CLEAR 确认：",
            "This will clear all four recurring schedule slots.\nEnter CLEAR to confirm: ",
        )
    ).strip()
    if answer != "CLEAR":
        raise ScheduleError(
            ui(
                "操作已取消，没有发送写入包",
                "Operation cancelled; no write packet was sent",
            )
        )


def write_and_verify(
    client: LanClient,
    device: Device,
    desired: list[ScheduleSlot],
    verifier: Callable[[list[ScheduleSlot]], bool],
) -> list[ScheduleSlot]:
    # Never write without a successful read in the same socket session.
    client.query(device)
    client.write_once(device, desired)
    time.sleep(0.9)
    current = client.query(device)
    if not verifier(current):
        raise ScheduleError(
            ui(
                "写入后的回读结果不匹配；没有自动重发，请检查设备当前定时",
                "Read-back did not match; the write was not retried automatically",
            )
        )
    # A second independent read protects against accepting a delayed old packet.
    confirmed = client.query(device)
    if not verifier(confirmed):
        raise ScheduleError(
            ui(
                "第二次回读结果不一致；请不要继续写入并检查网络",
                "The second read-back differed; stop writing and check the network",
            )
        )
    return confirmed


def command_scan(args: argparse.Namespace) -> int:
    with LanClient(args.timeout) as client:
        devices = scan_devices(client, args.subnet, args.timeout)
    print_devices(devices, args.json)
    return 0 if devices else 1


def command_device(args: argparse.Namespace) -> int:
    with LanClient(args.timeout) as client:
        device = connect_device(client, args)
        current = client.query(device)
        if args.command == "query":
            print_schedule(current, args.json)
            return 0

        desired = list(current)
        if args.command == "set":
            desired[args.slot - 1] = ScheduleSlot.configured(
                args.turn_on,
                args.turn_off,
                parse_days(args.days),
                not args.disabled,
            )
            expected = desired[args.slot - 1]
            verifier = lambda slots: slots[args.slot - 1].raw[:5] == expected.raw[:5]
        elif args.command in {"enable", "disable"}:
            desired[args.slot - 1] = desired[args.slot - 1].with_enabled(
                args.command == "enable"
            )
            enabled = args.command == "enable"
            verifier = lambda slots: (
                not slots[args.slot - 1].empty
                and slots[args.slot - 1].enabled == enabled
            )
        elif args.command == "clear":
            desired = [ScheduleSlot.blank() for _ in range(4)]
            verifier = lambda slots: all(slot.empty for slot in slots)
            require_clear_confirmation(args)
        else:
            raise ScheduleError(f"未知操作 {args.command}")

        confirmed = write_and_verify(client, device, desired, verifier)
        print("操作成功，设备已连续两次回读确认：")
        print_schedule(confirmed, args.json)
        return 0


def prompt_choice(prompt: str, minimum: int, maximum: int) -> int:
    while True:
        answer = input(prompt).strip()
        if answer.isdigit() and minimum <= int(answer) <= maximum:
            return int(answer)
        print(
            ui(
                f"请输入 {minimum} 到 {maximum}。",
                f"Enter a number from {minimum} to {maximum}.",
            )
        )


def interactive_pick_device(client: LanClient) -> Device:
    while True:
        print(
            ui(
                "\n设备来源：\n1. 扫描本地网络\n2. 手动输入 IP",
                "\nDevice source:\n1. Scan local network\n2. Enter IP manually",
            )
        )
        choice = prompt_choice(ui("选择：", "Choice: "), 1, 2)
        if choice == 1:
            subnet = (
                input(
                    ui(
                        "扫描网段（直接回车自动判断）：",
                        "Subnet (press Enter to detect automatically): ",
                    )
                ).strip()
                or None
            )
            devices = scan_devices(client, subnet, PASSIVE_TIMEOUT)
            print_devices(devices)
            if not devices:
                print(
                    ui(
                        "扫描没有结果，已返回设备来源菜单，可重新扫描或手动输入。",
                        "No scan result. Returning to device source; scan again or enter an IP.",
                    )
                )
                continue
            selected = prompt_choice(
                ui("选择设备编号：", "Device number: "), 1, len(devices)
            )
            device = devices[selected - 1]
            client.learn_sequence(device.sequence)
            return device

        break

    host = str(ipaddress.ip_address(input(ui("设备 IP：", "Device IP: ")).strip()))
    mac = resolve_neighbor_mac(host)
    if mac:
        print(
            ui(
                f"已从邻居表找到 MAC：{display_mac(mac)}",
                f"MAC found in neighbor table: {display_mac(mac)}",
            )
        )
    else:
        print(
            ui(
                f"邻居表没有 MAC，正在监听状态广播，最多 {PASSIVE_TIMEOUT:g} 秒……",
                f"No MAC in neighbor table; listening for status broadcasts for up to {PASSIVE_TIMEOUT:g} seconds...",
            )
        )
        passive = client.wait_for_host_broadcast(host, PASSIVE_TIMEOUT)
        if passive is not None:
            print(
                ui(
                    f"已从状态广播找到 MAC：{display_mac(passive.mac)}",
                    f"MAC learned from status broadcast: {display_mac(passive.mac)}",
                )
            )
            return passive
        mac = normalize_mac(
            input(
                ui(
                    "未收到广播，请填写设备 MAC：",
                    "No broadcast received; enter device MAC: ",
                )
            ).strip()
        )
    discovered = client.discover(host, mac)
    if discovered is not None:
        return discovered

    print(
        ui(
            "设备未回复发现请求，请选择手动型号：",
            "Discovery did not respond; select the model manually:",
        )
    )
    models = list(MODEL_PROFILES)
    for index, model in enumerate(models, 1):
        print(f"{index}. {model}")
    model = models[prompt_choice(ui("选择：", "Choice: "), 1, len(models)) - 1]
    default_auth = MODEL_PROFILES[model][1]
    auth_text = input(
        ui(
            f"鉴权码（回车使用 {default_auth:04X}）：",
            f"Authentication code (Enter for {default_auth:04X}): ",
        )
    ).strip()
    auth = default_auth if not auth_text else parse_hex_u16(auth_text)
    return fallback_device(host, mac, model, 0xF1, auth)


def interactive() -> int:
    choose_language()
    print(
        ui(
            "352Air 本机循环定时管理器",
            "352Air Recurring Schedule Manager",
        )
    )
    print(
        ui(
            "仅访问局域网 UDP 11530，不连接 352 云服务。",
            "Uses LAN UDP 11530 only; never connects to the 352 cloud service.",
        )
    )
    while True:
        try:
            with LanClient() as client:
                device = interactive_pick_device(client)
                print(
                    ui(
                        f"\n已选择：{device.host}  "
                        f"{display_mac(device.mac)}  {device.family_name}",
                        f"\nSelected: {device.host}  "
                        f"{display_mac(device.mac)}  {device.family_name}",
                    )
                )
                if not interactive_device_menu(client, device):
                    return 0
        except (ScheduleError, ValueError, OSError, argparse.ArgumentTypeError) as exc:
            print(ui(f"\n错误：{exc}", f"\nError: {exc}"))
            if not retry_prompt("返回设备选择", "return to device selection"):
                return 1


def retry_prompt(destination_zh: str, destination_en: str) -> bool:
    """Pause after an interactive error instead of terminating the program."""
    try:
        answer = input(
            ui(
                f"按回车{destination_zh}，输入 q 退出：",
                f"Press Enter to {destination_en}, or q to quit: ",
            )
        ).strip().lower()
    except EOFError:
        return False
    return answer not in {"q", "quit", "退出"}


def interactive_device_menu(client: LanClient, device: Device) -> bool:
    """Run one device menu; return True to choose another device."""
    try:
        print(ui("\n当前定时：", "\nCurrent schedules:"))
        print_schedule(client.query(device))
    except (ScheduleError, ValueError, OSError, argparse.ArgumentTypeError) as exc:
        print(
            ui(
                f"\n首次查询失败：{exc}\n可在菜单选择 1 重试。",
                f"\nInitial query failed: {exc}\nChoose 1 in the menu to retry.",
            )
        )
    while True:
        print(
            ui(
                "\n1. 查询定时\n2. 设置/覆盖定时槽\n3. 启用定时槽"
                "\n4. 停用定时槽\n5. 清除全部定时\n6. 重新选择设备\n0. 退出",
                "\n1. Query schedules\n2. Set/replace a slot\n3. Enable a slot"
                "\n4. Disable a slot\n5. Clear all schedules\n6. Choose another device\n0. Exit",
            )
        )
        choice = prompt_choice(ui("选择：", "Choice: "), 0, 6)
        if choice == 0:
            return False
        if choice == 6:
            return True
        try:
            current = client.query(device)
            print_schedule(current)
            if choice == 1:
                continue
            if choice == 2:
                slot = prompt_choice(ui("定时槽（1-4）：", "Schedule slot (1-4): "), 1, 4)
                turn_on = input(
                    ui(
                        "开机时间（如 1700，不设置填 -）：",
                        "Turn-on time (e.g. 1700, or - for none): ",
                    )
                ).strip()
                turn_off = input(
                    ui(
                        "关机时间（如 0900，不设置填 -）：",
                        "Turn-off time (e.g. 0900, or - for none): ",
                    )
                ).strip()
                days = input(
                    ui(
                        "星期（1=周一…7=周日；如 135；每天填 all）：",
                        "Days (1=Mon...7=Sun; e.g. 135; use all for daily): ",
                    )
                ).strip()
                enabled = input(
                    ui("立即启用？[Y/n]：", "Enable now? [Y/n]: ")
                ).strip().lower() not in {
                    "n",
                    "no",
                    "否",
                }
                desired = list(current)
                desired[slot - 1] = ScheduleSlot.configured(
                    turn_on, turn_off, parse_days(days), enabled
                )
                expected = desired[slot - 1]
                confirmed = write_and_verify(
                    client,
                    device,
                    desired,
                    lambda slots: slots[slot - 1].raw[:5] == expected.raw[:5],
                )
            elif choice in {3, 4}:
                slot = prompt_choice(
                    ui("定时槽（1-4）：", "Schedule slot (1-4): "), 1, 4
                )
                enabled = choice == 3
                desired = list(current)
                desired[slot - 1] = desired[slot - 1].with_enabled(enabled)
                confirmed = write_and_verify(
                    client,
                    device,
                    desired,
                    lambda slots: (
                        not slots[slot - 1].empty
                        and slots[slot - 1].enabled == enabled
                    ),
                )
            else:
                if input(
                    ui(
                        "输入 CLEAR 确认清除全部 4 个槽：",
                        "Enter CLEAR to clear all four slots: ",
                    )
                ).strip() != "CLEAR":
                    print(ui("已取消。", "Cancelled."))
                    continue
                desired = [ScheduleSlot.blank() for _ in range(4)]
                confirmed = write_and_verify(
                    client,
                    device,
                    desired,
                    lambda slots: all(slot.empty for slot in slots),
                )
            print(
                ui(
                    "操作成功，连续两次回读一致：",
                    "Success; two consecutive read-backs matched:",
                )
            )
            print_schedule(confirmed)
        except (ScheduleError, ValueError, OSError, argparse.ArgumentTypeError) as exc:
            print(ui(f"\n错误：{exc}", f"\nError: {exc}"))
            if not retry_prompt("返回当前设备菜单", "return to this device menu"):
                return False


def add_device_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", required=True, help="净化器 IPv4 地址")
    parser.add_argument("--mac", help="设备 MAC；同网段时可从邻居表自动取得")
    parser.add_argument(
        "--model", choices=sorted(MODEL_PROFILES), help="发现失败时的型号回退"
    )
    parser.add_argument(
        "--company", type=parse_hex_u8, help="发现失败时的 company 十六进制值"
    )
    parser.add_argument(
        "--auth", type=parse_hex_u16, help="发现失败时的鉴权码十六进制值"
    )
    parser.add_argument(
        "--timeout", type=float, default=2.5, help="每次查询等待秒数（默认 2.5）"
    )
    parser.add_argument(
        "--passive-timeout",
        type=float,
        default=PASSIVE_TIMEOUT,
        help=f"邻居表无 MAC 时监听状态广播的秒数（默认 {PASSIVE_TIMEOUT:g}）",
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 输出查询结果")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="352Air Schedule Manager")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="扫描本地 352 设备")
    scan.add_argument("--subnet", help="要扫描的 IPv4 CIDR 网段")
    scan.add_argument(
        "--timeout",
        type=float,
        default=PASSIVE_TIMEOUT,
        help=f"无主动发现结果时监听广播的秒数（默认 {PASSIVE_TIMEOUT:g}）",
    )
    scan.add_argument("--json", action="store_true")

    query = subparsers.add_parser("query", help="查询 4 个循环定时槽")
    add_device_arguments(query)

    set_timer = subparsers.add_parser("set", help="设置或覆盖一个定时槽")
    add_device_arguments(set_timer)
    set_timer.add_argument("--slot", type=int, choices=range(1, 5), required=True)
    set_timer.add_argument(
        "--on", dest="turn_on", default="-", help="开机时间，如 1700；- 表示不设置"
    )
    set_timer.add_argument(
        "--off", dest="turn_off", default="-", help="关机时间，如 0900；- 表示不设置"
    )
    set_timer.add_argument(
        "--days", default="all", help="星期，如 135；每天使用 1234567 或 all"
    )
    set_timer.add_argument("--disabled", action="store_true", help="写入但暂不启用")
    # Accepted as a no-op for compatibility with commands from older versions.
    set_timer.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)

    for name, help_text in (
        ("enable", "启用一个已有定时槽"),
        ("disable", "停用一个定时槽"),
    ):
        action = subparsers.add_parser(name, help=help_text)
        add_device_arguments(action)
        action.add_argument("--slot", type=int, choices=range(1, 5), required=True)
        action.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)

    clear = subparsers.add_parser("clear", help="清除全部 4 个循环定时槽")
    add_device_arguments(clear)
    clear.add_argument("--yes", action="store_true", help="跳过输入 CLEAR 的确认")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            return interactive()
        if args.command == "scan":
            return command_scan(args)
        return command_device(args)
    except (ScheduleError, ValueError, OSError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
