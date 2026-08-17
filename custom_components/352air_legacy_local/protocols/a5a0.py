# SPDX-License-Identifier: GPL-3.0-or-later
"""Codec for the routed ``01 A5 A0`` purifier family."""

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
    PowerState,
    ProtocolFamily,
    known_mode,
)
from .base import (
    DeviceCodec,
    build_outer_frame,
    outer_metadata,
    parse_outer_frame,
    valid_source,
)

_ROUTE = 0x01
_PREFIX = b"\xa5\xa0"
_STATE_PAYLOAD_LENGTH = 33  # 16-byte envelope + 33-byte payload = 49 bytes.

_COMMAND_CODES = {
    CommandOperation.MODE: 0x51,
    CommandOperation.SPEED: 0x52,
    CommandOperation.PTC: 0x53,
    CommandOperation.TIMER: 0x54,
    CommandOperation.CHILD_LOCK: 0x55,
    CommandOperation.DISPLAY: 0x56,
    CommandOperation.FILTER_OPERATION: 0x57,
    CommandOperation.POWER: 0x5E,
}


class A5A0Codec(DeviceCodec):
    """Pure encoder/decoder for wire type 2 A5A0 devices."""

    family = ProtocolFamily.A5A0

    def encode_query(self, context: CommandContext) -> bytes:
        """Encode the documented fixed state query."""

        self._check_identity(context.identity)
        return build_outer_frame(context, b"\x01\xa5\xa0\x11\x11\x00\x00")

    def encode_command(self, context: CommandContext, command: Command) -> bytes:
        """Encode a documented A5A0 control with its additive checksum."""

        self._check_identity(context.identity)
        command_code = _COMMAND_CODES.get(command.operation)
        if command_code is None:
            raise InvalidCommandError(
                f"{command.operation.value} is not an A5A0 command"
            )
        _validate_a5_value(command)
        inner_without_checksum = bytes(
            (_PREFIX[0], _PREFIX[1], command_code, command.value, 0)
        )
        checksum = sum(inner_without_checksum) & 0xFF
        return build_outer_frame(
            context, bytes((_ROUTE,)) + inner_without_checksum + bytes((checksum,))
        )

    def decode(self, datagram: bytes, source: tuple[str, int]) -> DecodedPacket | None:
        """Decode only fully framed A5A0 state or checksummed ACK traffic."""

        outer = parse_outer_frame(datagram)
        peer = valid_source(source)
        if outer is None or peer is None or outer.identity.wire_type != 2:
            return None
        payload = outer.payload
        if len(payload) >= 3 and payload[0] == _ROUTE and payload[1:3] == _PREFIX:
            if len(payload) == _STATE_PAYLOAD_LENGTH:
                return self._decode_state(
                    outer.identity, outer.sequence, payload, peer, outer_metadata(outer)
                )
            if len(payload) == 7 and _valid_control_checksum(payload):
                metadata = outer_metadata(outer)
                metadata["command"] = payload[3]
                metadata["value"] = payload[4]
                return DecodedPacket(
                    identity=outer.identity,
                    sequence=outer.sequence,
                    kind=PacketKind.ACK,
                    state=None,
                    source=peer,
                    family=self.family,
                    raw_metadata=metadata,
                )
        return None

    @staticmethod
    def _check_identity(identity: HeaderIdentity) -> None:
        if identity.wire_type != 2:
            raise InvalidCommandError("A5A0 requires a learned wire type of 2")

    def _decode_state(
        self,
        identity: HeaderIdentity,
        sequence: int,
        payload: bytes,
        source: tuple[str, int],
        metadata: dict[str, int | bytes | str],
    ) -> DecodedPacket:
        # The documented absolute offsets start at payload index three.
        packed = payload[3]
        raw_speed = payload[4]
        raw_timer = payload[5]
        raw_air_quality = payload[6]
        raw_lock = payload[7]
        raw_display = payload[8]
        raw_power = payload[9]
        processed_exponent = payload[21]
        processed_base = int.from_bytes(payload[22:24], "big")
        purified_exponent = payload[24]
        purified_base = int.from_bytes(payload[25:27], "big")

        raw_values: dict[str, int] = {
            "mode_raw": packed & 0x0F,
            "speed_raw": raw_speed,
            "timer_hours_raw": raw_timer,
            "air_quality_raw": raw_air_quality,
            "child_lock_raw": raw_lock,
            "display_raw": raw_display,
            "power_raw": raw_power,
        }
        child_lock = _a5_bool(raw_lock)
        display_on = _a5_display(raw_display)
        power = _a5_power(raw_power)
        if child_lock is None:
            raw_values["child_lock_unknown"] = raw_lock
        if display_on is None:
            raw_values["display_unknown"] = raw_display
        if power is None:
            raw_values["power_unknown"] = raw_power

        processed_air = _safe_cumulative_volume(processed_base, processed_exponent)
        purified_air = _safe_cumulative_volume(purified_base, purified_exponent)
        if processed_air is None:
            raw_values["processed_air_exponent_unusable"] = processed_exponent
        if purified_air is None:
            raw_values["purified_air_exponent_unusable"] = purified_exponent

        state = DeviceState(
            mode=known_mode(packed & 0x0F),
            filter_type_raw=packed >> 4,
            speed=raw_speed if 1 <= raw_speed <= 6 else None,
            timer_hours=raw_timer if raw_timer in {0, 1, 2, 3, 5, 8} else None,
            air_quality_raw=raw_air_quality,
            child_lock=child_lock,
            display_on=display_on,
            power=power,
            timer_remaining_minutes=int.from_bytes(payload[10:12], "big"),
            pm25=int.from_bytes(payload[12:14], "big"),
            processed_air_m3=processed_air,
            purified_air_m3=purified_air,
            processed_air_exponent=processed_exponent,
            processed_air_base=processed_base,
            purified_air_exponent=purified_exponent,
            purified_air_base=purified_base,
            raw_values=raw_values,
        )
        return DecodedPacket(
            identity=identity,
            sequence=sequence,
            kind=PacketKind.STATE,
            state=state,
            source=source,
            family=self.family,
            raw_metadata=metadata,
        )


def _valid_control_checksum(payload: bytes) -> bool:
    return sum(payload[1:6]) & 0xFF == payload[6]


def _validate_a5_value(command: Command) -> None:
    value = command.value
    valid_values = {
        CommandOperation.MODE: {1, 2, 3, 5},
        CommandOperation.SPEED: set(range(1, 7)),
        CommandOperation.PTC: {0, 1, 2},
        CommandOperation.TIMER: {0, 1, 2, 3, 5, 8},
        CommandOperation.CHILD_LOCK: {0x00, 0x11},
        CommandOperation.DISPLAY: {0x00, 0x11},
        CommandOperation.FILTER_OPERATION: {1, 2, 3},
        CommandOperation.POWER: {0x35, 0x11},
    }
    if value not in valid_values[command.operation]:
        raise InvalidCommandError(
            f"invalid A5A0 value {value:#x} for {command.operation.value}"
        )


def _a5_bool(value: int) -> bool | None:
    if value == 0x00:
        return False
    if value == 0x11:
        return True
    return None


def _a5_display(value: int) -> bool | None:
    if value == 0x00:
        return True
    if value == 0x11:
        return False
    return None


def _a5_power(value: int) -> PowerState | None:
    if value == 0x00:
        return PowerState.ON
    if value == 0x11:
        return PowerState.OFF
    return None


def _safe_cumulative_volume(base: int, exponent: int) -> int | None:
    """Avoid publishing an unbounded diagnostic number from arbitrary bytes."""

    # The retired app defined multipliers only for exponents 0 through 3.
    if not 0 <= exponent <= 3:
        return None
    return base * (1, 10, 100, 1000)[exponent]
