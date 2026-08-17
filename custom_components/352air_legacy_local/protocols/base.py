# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared framing and validation for 352's UDP protocol families."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..models import (
    Command,
    CommandContext,
    DecodedPacket,
    Endpoint,
    HeaderIdentity,
    ProtocolFamily,
)

OUTER_MARKER = 0xA1
OUTER_HEADER_LENGTH = 16
NORMAL_OUTER_OPERATION = 0x04
DISCOVERY_OUTER_OPERATION = 0x04


@dataclass(frozen=True, slots=True)
class OuterFrame:
    """A validated UDP envelope, before its routed body is interpreted."""

    identity: HeaderIdentity
    operation: int
    sequence: int
    payload: bytes


class DeviceCodec(Protocol):
    """Family codec API used by the asynchronous transport."""

    family: ProtocolFamily

    def encode_query(self, context: CommandContext) -> bytes:
        """Build a deterministic, read-only state query."""

    def encode_command(self, context: CommandContext, command: Command) -> bytes:
        """Build a deterministic command datagram."""

    def decode(self, datagram: bytes, source: Endpoint) -> DecodedPacket | None:
        """Decode trusted family traffic or ignore unrelated/malformed traffic."""


def build_outer_frame(
    context: CommandContext,
    payload: bytes,
    *,
    operation: int | None = None,
    identity: HeaderIdentity | None = None,
) -> bytes:
    """Wrap a routed payload in the documented outer envelope."""

    routed_payload = bytes(payload)
    if len(routed_payload) > 0xF8:
        raise ValueError("routed payload is too large for the outer envelope")
    header = identity or context.identity
    operation_byte = context.outer_operation if operation is None else operation
    if not 0 <= operation_byte <= 0xFF:
        raise ValueError("outer operation must fit in one byte")
    return b"".join(
        (
            bytes((OUTER_MARKER, operation_byte)),
            header.mac,
            bytes((len(routed_payload) + 7, 0)),
            context.outer_sequence.to_bytes(2, "big"),
            bytes((header.company, header.wire_type)),
            header.auth.to_bytes(2, "big"),
            routed_payload,
        )
    )


def parse_outer_frame(datagram: bytes | bytearray | memoryview) -> OuterFrame | None:
    """Return an envelope only if all declared framing lengths agree exactly."""

    if not isinstance(datagram, (bytes, bytearray, memoryview)):
        return None
    data = bytes(datagram)
    if len(data) < OUTER_HEADER_LENGTH or data[0] != OUTER_MARKER:
        return None
    encoded_length = data[8]
    if encoded_length < 7:
        return None
    payload_length = encoded_length - 7
    if len(data) != OUTER_HEADER_LENGTH + payload_length:
        return None
    try:
        identity = HeaderIdentity(
            mac=data[2:8],
            company=data[12],
            wire_type=data[13],
            auth=int.from_bytes(data[14:16], "big"),
        )
    except (TypeError, ValueError):
        return None
    return OuterFrame(
        identity=identity,
        operation=data[1],
        sequence=int.from_bytes(data[10:12], "big"),
        payload=data[16:],
    )


def valid_source(source: object) -> Endpoint | None:
    """Defensively validate an asyncio UDP peer tuple."""

    if not isinstance(source, tuple) or len(source) != 2:
        return None
    host, port = source
    if not isinstance(host, str) or isinstance(port, bool) or not isinstance(port, int):
        return None
    if not 0 <= port <= 0xFFFF:
        return None
    return host, port


def crc16_genibus(data: bytes | bytearray | memoryview) -> int:
    """Return CRC-16/GENIBUS (poly 0x1021, init/xor-out 0xFFFF)."""

    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (
                ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
            )
    return crc ^ 0xFFFF


def f072_crc_is_valid(frame: bytes) -> bool:
    """Validate either the documented request or known response CRC layout."""

    return f072_request_crc_is_valid(frame) or f072_response_crc_is_valid(frame)


def f072_request_crc_is_valid(frame: bytes) -> bool:
    """Validate a 15-byte-style outgoing/request F072 inner frame."""

    if len(frame) < 15 or frame[:2] != b"\xf0\x72":
        return False
    declared_length = int.from_bytes(frame[2:4], "big")
    if declared_length != len(frame) - 2:
        return False
    expected_crc = int.from_bytes(frame[-2:], "big")
    return crc16_genibus(frame[2:-2]) == expected_crc


def f072_response_crc_is_valid(frame: bytes) -> bool:
    """Validate the distinct observed response CRC range.

    Response parser facts establish the CRC input as bytes from offset three
    through the byte before the trailing two-byte CRC.  The outer envelope has
    already supplied the only documented response-length check.
    """

    if len(frame) < 10 or frame[:2] != b"\xf0\x72":
        return False
    expected_crc = int.from_bytes(frame[-2:], "big")
    return crc16_genibus(frame[3:-2]) == expected_crc


def outer_metadata(frame: OuterFrame) -> dict[str, int | bytes | str]:
    """Small, non-semantic framing facts useful to diagnostics."""

    return {
        "outer_operation": frame.operation,
        "payload_length": len(frame.payload),
    }
