# SPDX-License-Identifier: GPL-3.0-or-later
"""Codec for the M25 detector's restricted FA/E5 local family."""

from __future__ import annotations

from ..models import (
    Command,
    CommandContext,
    CommandOperation,
    DecodedPacket,
    DeviceState,
    HeaderIdentity,
    InvalidCommandError,
    PacketKind,
    ProtocolFamily,
)
from .base import (
    DeviceCodec,
    build_outer_frame,
    outer_metadata,
    parse_outer_frame,
    valid_source,
)

_ROUTE = 0x03


class M25Codec(DeviceCodec):
    """Encode only documented detector reads and backlight operations."""

    family = ProtocolFamily.M25

    def encode_query(self, context: CommandContext) -> bytes:
        """Encode the documented sensor-state read; it changes no device state."""

        self._check_identity(context.identity)
        return build_outer_frame(context, b"\x03\xfa\xa0\x11\x11\x00\x00")

    def encode_backlight_query(self, context: CommandContext) -> bytes:
        """Encode the documented read-only backlight query."""

        self._check_identity(context.identity)
        return build_outer_frame(context, b"\x03\xfa\xa4\x02\x01\xa1")

    def encode_command(self, context: CommandContext, command: Command) -> bytes:
        """Encode a five-minute or always-on backlight selection only."""

        self._check_identity(context.identity)
        if command.operation is not CommandOperation.BACKLIGHT or command.value not in {
            0,
            1,
        }:
            raise InvalidCommandError(
                "M25 supports only BACKLIGHT values 0 (five-minute) and 1 (always-on)"
            )
        checksum = 0xA1 if command.value == 0 else 0xA2
        payload = bytes((_ROUTE, 0xFA, 0xA3, 0x03, 0x01, command.value, checksum))
        return build_outer_frame(context, payload)

    def decode(self, datagram: bytes, source: tuple[str, int]) -> DecodedPacket | None:
        """Classify documented E5 forms without inventing undocumented sensors."""

        outer = parse_outer_frame(datagram)
        peer = valid_source(source)
        if outer is None or peer is None or outer.identity.wire_type != 1:
            return None
        payload = outer.payload
        if len(payload) < 3 or payload[:2] != b"\x03\xe5":
            return None
        response_form = payload[2]
        metadata = outer_metadata(outer)
        metadata["m25_response_form"] = response_form
        if response_form in {0xA1, 0xA2}:
            if len(payload) != 17:
                return None
            state = DeviceState(
                pm25=int.from_bytes(payload[3:5], "big"),
                linkage_raw=payload[7],
                raw_values={
                    "m25_response_form": response_form,
                    "linkage_raw": payload[7],
                },
            )
            return DecodedPacket(
                identity=outer.identity,
                sequence=outer.sequence,
                kind=PacketKind.STATE,
                state=state,
                source=peer,
                family=self.family,
                raw_metadata=metadata,
            )
        if response_form == 0xA3:
            if len(payload) != 7 or payload[3:5] != b"\x03\x01":
                return None
            state = DeviceState(backlight=payload[5])
            return DecodedPacket(
                identity=outer.identity,
                sequence=outer.sequence,
                kind=PacketKind.BACKLIGHT,
                state=state,
                source=peer,
                family=self.family,
                raw_metadata=metadata,
            )
        if response_form == 0xA4 and len(payload) >= 6 and payload[4] == 0x01:
            state = DeviceState(backlight=payload[5])
            return DecodedPacket(
                identity=outer.identity,
                sequence=outer.sequence,
                kind=PacketKind.BACKLIGHT,
                state=state,
                source=peer,
                family=self.family,
                raw_metadata=metadata,
            )
        return None

    @staticmethod
    def _check_identity(identity: HeaderIdentity) -> None:
        if identity.wire_type != 1:
            raise InvalidCommandError("M25 requires a learned wire type of 1")
