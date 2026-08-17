# SPDX-License-Identifier: GPL-3.0-or-later
"""Safe cleanup of the purifier's four persistent local schedule slots."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from time import monotonic_ns

from .const import UDP_PORT, mac_to_bytes
from .discovery import DiscoveryResult
from .models import CommandContext, HeaderIdentity
from .protocols.base import build_outer_frame, crc16_genibus, parse_outer_frame
from .udp import (
    SharedUdpEndpoint,
    async_acquire_udp_endpoint,
    async_release_udp_endpoint,
)

_SCHEDULE_WIRE_TYPES = frozenset({2, 3, 4})
_EMPTY_SLOT = b"\x00\xff\xff\xff\xff\x00\x00\x00"
_RESPONSE_TIMEOUT_SECONDS = 2.5
_QUERY_ATTEMPTS = 3
_WRITE_SETTLE_SECONDS = 0.9


class ScheduleCleanupError(Exception):
    """The local schedule could not be read, cleared, or verified."""


@dataclass(frozen=True, slots=True)
class ScheduleCleanupResult:
    """Non-sensitive result of a verified cleanup operation."""

    configured_slots_removed: int


def schedule_cleanup_supported(wire_type: int) -> bool:
    """Return whether the retired app defines purifier schedules for a family."""
    return wire_type in _SCHEDULE_WIRE_TYPES


class _ScheduleReceiver:
    """Collect only valid schedule replies from one discovered purifier."""

    def __init__(self, device: DiscoveryResult) -> None:
        self._device = device
        self._queue: asyncio.Queue[tuple[bytes, bytes, bytes, bytes]] = asyncio.Queue()

    def datagram_received(self, data: bytes, source: tuple[str, int]) -> None:
        slots = _decode_schedule_response(data, source, self._device)
        if slots is not None:
            self._queue.put_nowait(slots)

    def drain(self) -> None:
        """Discard duplicates that arrived before the next request."""
        with suppress(asyncio.QueueEmpty):
            while True:
                self._queue.get_nowait()

    async def receive(self) -> tuple[bytes, bytes, bytes, bytes]:
        """Wait for one fully validated response."""
        return await self._queue.get()


async def async_clear_local_schedules(
    device: DiscoveryResult,
) -> ScheduleCleanupResult:
    """Clear all four recurring on/off slots and verify two independent reads.

    The write is intentionally sent once. A successful return requires a valid
    read before the write and two valid empty reads afterwards; an ambiguous
    timeout is reported instead of automatically repeating a destructive write.
    """
    if not schedule_cleanup_supported(device.wire_type):
        raise ScheduleCleanupError("This device family has no purifier schedule")

    receiver = _ScheduleReceiver(device)
    try:
        endpoint = await async_acquire_udp_endpoint(receiver.datagram_received)
    except OSError as err:
        raise ScheduleCleanupError("Unable to open the local UDP endpoint") from err

    sequence = int(monotonic_ns() // 1_000_000) & 0xFFFF

    def next_sequence() -> int:
        nonlocal sequence
        sequence = (sequence + 1) & 0xFFFF
        return sequence

    try:
        previous = await _async_query_schedules(
            endpoint, receiver, device, next_sequence
        )
        endpoint.sendto(
            _encode_schedule_write(
                device,
                next_sequence(),
                (_EMPTY_SLOT, _EMPTY_SLOT, _EMPTY_SLOT, _EMPTY_SLOT),
            ),
            (device.host, UDP_PORT),
        )
        await asyncio.sleep(_WRITE_SETTLE_SECONDS)

        await _async_query_schedules(
            endpoint,
            receiver,
            device,
            next_sequence,
            require_empty=True,
        )
        await _async_query_schedules(
            endpoint,
            receiver,
            device,
            next_sequence,
            require_empty=True,
        )
    except asyncio.CancelledError:
        raise
    except (OSError, TimeoutError) as err:
        raise ScheduleCleanupError(
            "The purifier did not confirm its local schedule state"
        ) from err
    finally:
        await async_release_udp_endpoint(endpoint, receiver.datagram_received)

    return ScheduleCleanupResult(
        configured_slots_removed=sum(not _slot_is_empty(slot) for slot in previous)
    )


async def _async_query_schedules(
    endpoint: SharedUdpEndpoint,
    receiver: _ScheduleReceiver,
    device: DiscoveryResult,
    next_sequence: Callable[[], int],
    *,
    require_empty: bool = False,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Read schedule slots, optionally ignoring stale non-empty duplicates."""
    received_non_empty = False
    loop = asyncio.get_running_loop()
    for _attempt in range(_QUERY_ATTEMPTS):
        receiver.drain()
        sequence = next_sequence()
        endpoint.sendto(
            _encode_schedule_query(device, sequence),
            (device.host, UDP_PORT),
        )
        deadline = loop.time() + _RESPONSE_TIMEOUT_SECONDS
        while (remaining := deadline - loop.time()) > 0:
            try:
                async with asyncio.timeout(remaining):
                    slots = await receiver.receive()
            except TimeoutError:
                break
            if not require_empty or all(_slot_is_empty(slot) for slot in slots):
                return slots
            received_non_empty = True

    if received_non_empty:
        raise ScheduleCleanupError("The purifier retained one or more schedule slots")
    raise ScheduleCleanupError("The purifier did not answer the schedule query")


def _identity(device: DiscoveryResult) -> HeaderIdentity:
    return HeaderIdentity(
        mac=mac_to_bytes(device.mac),
        company=device.company,
        wire_type=device.wire_type,
        auth=device.auth,
    )


def _wrap_inner(device: DiscoveryResult, sequence: int, inner: bytes) -> bytes:
    context = CommandContext(
        identity=_identity(device),
        outer_sequence=sequence,
        inner_sequence=sequence,
    )
    return build_outer_frame(context, b"\x01" + inner)


def _encode_schedule_query(device: DiscoveryResult, sequence: int) -> bytes:
    inner = bytearray(14)
    inner[0:4] = b"\xf0\x72\x00\x0c"
    inner[4:7] = bytes((device.wire_type, 0x04, 0x0C))
    inner[7:9] = sequence.to_bytes(2, "big")
    inner[9:12] = b"\x01\x04\x04"
    inner[12:14] = crc16_genibus(inner[2:12]).to_bytes(2, "big")
    return _wrap_inner(device, sequence, bytes(inner))


def _encode_schedule_write(
    device: DiscoveryResult,
    sequence: int,
    slots: tuple[bytes, bytes, bytes, bytes],
) -> bytes:
    if any(len(slot) != 8 for slot in slots):
        raise ValueError("Each schedule slot must contain eight bytes")
    body = b"\x04\x20" + b"".join(slots)
    inner = bytearray(47)
    inner[0:4] = b"\xf0\x72\x00\x2d"
    inner[4:7] = bytes((device.wire_type, 0x04, 0x0B))
    inner[7:9] = sequence.to_bytes(2, "big")
    inner[9] = len(body)
    inner[10:44] = body
    inner[44] = sum(body) & 0xFF
    inner[45:47] = crc16_genibus(inner[2:45]).to_bytes(2, "big")
    return _wrap_inner(device, sequence, bytes(inner))


def _decode_schedule_response(
    datagram: bytes,
    source: tuple[str, int],
    device: DiscoveryResult,
) -> tuple[bytes, bytes, bytes, bytes] | None:
    if source[0] != device.host:
        return None
    outer = parse_outer_frame(datagram)
    expected_mac = mac_to_bytes(device.mac)
    if (
        outer is None
        or outer.identity.mac != expected_mac
        or outer.identity.company != device.company
        or outer.identity.wire_type != device.wire_type
        or outer.identity.auth != device.auth
        or len(outer.payload) < 48
        or outer.payload[0] != 0x02
    ):
        return None

    inner = outer.payload[1:]
    if len(inner) < 47 or inner[:2] != b"\xf0\x72":
        return None
    declared_length = int.from_bytes(inner[2:4], "big") + 2
    if declared_length < 47 or declared_length > len(inner):
        return None
    inner = inner[:declared_length]
    if (
        inner[4] != device.wire_type
        or inner[5] not in {0x84, 0x03}
        or inner[6] != 0x0C
        or inner[10:12] != b"\x04\x20"
        or crc16_genibus(inner[2:-2]) != int.from_bytes(inner[-2:], "big")
    ):
        return None

    slots = tuple(bytes(inner[12 + index * 8 : 20 + index * 8]) for index in range(4))
    if any(len(slot) != 8 for slot in slots):
        return None
    return slots[0], slots[1], slots[2], slots[3]


def _slot_is_empty(slot: bytes) -> bool:
    """Accept both empty representations observed by the retired app."""
    return all(value == 0 for value in slot[:6]) or slot[1:5] == b"\xff" * 4
