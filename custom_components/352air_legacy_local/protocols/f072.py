# SPDX-License-Identifier: GPL-3.0-or-later
"""Codec for F072 X50-family and G30/G45-family routed packets."""

from __future__ import annotations

from ..models import (
    Command,
    CommandContext,
    CommandOperation,
    DecodedPacket,
    DeviceModel,
    DeviceState,
    HeaderIdentity,
    InvalidCommandError,
    ModeValue,
    PacketKind,
    PowerState,
    ProtocolFamily,
    family_for_model,
    known_mode,
)
from .base import (
    DeviceCodec,
    build_outer_frame,
    crc16_genibus,
    f072_response_crc_is_valid,
    outer_metadata,
    parse_outer_frame,
    valid_source,
)

_ROUTE = 0x01
_PREFIX = b"\xf0\x72"

_X50_COMMANDS = {
    CommandOperation.MODE: 0x51,
    CommandOperation.SPEED: 0x52,
    CommandOperation.PTC: 0x53,
    CommandOperation.TIMER: 0x54,
    CommandOperation.CHILD_LOCK: 0x55,
    CommandOperation.DISPLAY: 0x56,
    CommandOperation.POWER: 0x5E,
}
_G30_COMMANDS = {
    CommandOperation.MODE: 0x51,
    CommandOperation.PTC: 0x53,
    CommandOperation.TIMER: 0x54,
    CommandOperation.CHILD_LOCK: 0x55,
    CommandOperation.DISPLAY: 0x56,
    CommandOperation.POWER: 0x5E,
}


class F072Codec(DeviceCodec):
    """Pure F072 codec configured for one documented inner family.

    ``model`` is optional because it is a product-layer selection rather than
    a wire claim.  It affects only the G45 maximum airflow used for outbound
    percentage conversion and inbound airflow bounds.
    """

    def __init__(
        self,
        family: ProtocolFamily = ProtocolFamily.F072_X50,
        model: DeviceModel | None = None,
    ) -> None:
        if family not in {ProtocolFamily.F072_X50, ProtocolFamily.F072_G30}:
            raise ValueError("F072Codec requires an F072 protocol family")
        if model is not None and family_for_model(model) is not family:
            raise ValueError("model does not belong to the requested F072 family")
        self.family = family
        self.model = model
        self._inner_type = 3 if family is ProtocolFamily.F072_X50 else 4
        self._wire_type = self._inner_type

    def encode_query(self, context: CommandContext) -> bytes:
        """Encode the documented F072 state query (11/11)."""

        self._check_identity(context.identity)
        inner = _single_value_frame(
            self._inner_type, context.inner_sequence, 0x11, 0x11
        )
        return build_outer_frame(context, bytes((_ROUTE,)) + inner)

    def encode_command(self, context: CommandContext, command: Command) -> bytes:
        """Encode one documented F072 control frame after strict validation."""

        self._check_identity(context.identity)
        if command.operation is CommandOperation.PERCENTAGE:
            return self._encode_percentage(context, command.value)
        if command.operation is CommandOperation.AIRFLOW:
            if self.family is not ProtocolFamily.F072_G30:
                raise InvalidCommandError("airflow is only documented for G30/G45")
            self._validate_flow(command.value, context)
            inner = _flow_frame(self._inner_type, context.inner_sequence, command.value)
            return build_outer_frame(context, bytes((_ROUTE,)) + inner)

        codes = (
            _X50_COMMANDS if self.family is ProtocolFamily.F072_X50 else _G30_COMMANDS
        )
        command_code = codes.get(command.operation)
        if command_code is None:
            raise InvalidCommandError(
                f"{command.operation.value} is not supported by {self.family.value}"
            )
        _validate_single_value(self.family, command)
        inner = _single_value_frame(
            self._inner_type, context.inner_sequence, command_code, command.value
        )
        return build_outer_frame(context, bytes((_ROUTE,)) + inner)

    def decode(self, datagram: bytes, source: tuple[str, int]) -> DecodedPacket | None:
        """Decode only outer-length- and CRC-valid F072 traffic for this family."""

        outer = parse_outer_frame(datagram)
        peer = valid_source(source)
        if outer is None or peer is None or outer.identity.wire_type != self._wire_type:
            return None
        payload = outer.payload
        if len(payload) < 16 or payload[0] != _ROUTE:
            return None
        frame = payload[1:]
        # Responses have a different header from the fixed 15-byte request.
        # Parser facts establish response marker byte 6 as 84 or 03, response
        # type byte 7 as 02, and the state area beginning at byte 8.
        if (
            not f072_response_crc_is_valid(frame)
            or frame[6] not in {0x84, 0x03}
            or frame[7] != 0x02
        ):
            return None

        inner_sequence = None
        data_area = frame[8:-2]
        metadata: dict[str, int | bytes | str] = outer_metadata(outer)
        metadata.update(
            {
                "response_inner_length": len(frame),
                "data_length": len(data_area),
                "response_marker": frame[6],
            }
        )
        if self.family is ProtocolFamily.F072_G30 and self._is_g30_state(data_area):
            return self._decode_g30_state(
                outer.identity,
                outer.sequence,
                inner_sequence,
                data_area,
                peer,
                metadata,
            )
        if self.family is ProtocolFamily.F072_X50 and self._is_x50_state(data_area):
            return self._decode_x50_state(
                outer.identity,
                outer.sequence,
                inner_sequence,
                data_area,
                peer,
                metadata,
            )
        if len(data_area) == 4:
            metadata["command"] = data_area[1]
            metadata["value"] = data_area[2]
            return DecodedPacket(
                identity=outer.identity,
                sequence=outer.sequence,
                kind=PacketKind.ACK,
                state=None,
                source=peer,
                family=self.family,
                inner_sequence=inner_sequence,
                raw_metadata=metadata,
            )
        return None

    def _encode_percentage(self, context: CommandContext, percentage: int) -> bytes:
        if self.family is not ProtocolFamily.F072_G30:
            raise InvalidCommandError(
                "percentage control is only documented for G30/G45"
            )
        if not 0 <= percentage <= 100:
            raise InvalidCommandError("percentage must be in the range 0..100")
        if percentage == 0:
            inner = _single_value_frame(
                self._inner_type, context.inner_sequence, 0x5E, 0x11
            )
        else:
            flow = self.flow_for_percentage(percentage, context)
            inner = _flow_frame(self._inner_type, context.inner_sequence, flow)
        return build_outer_frame(context, bytes((_ROUTE,)) + inner)

    def flow_for_percentage(self, percentage: int, context: CommandContext) -> int:
        """Map 1..100 to the documented stepped G30/G45 airflow range."""

        if self.family is not ProtocolFamily.F072_G30 or not 1 <= percentage <= 100:
            raise InvalidCommandError("percentage must be 1..100 for a G30/G45 device")
        minimum, maximum = self._flow_range(context)
        span = maximum - minimum
        # Round to nearest five with ties upward, avoiding platform float rules.
        step_count = (2 * (percentage - 1) * span + (99 * 5)) // (2 * 99 * 5)
        return minimum + step_count * 5

    def _flow_range(self, context: CommandContext) -> tuple[int, int]:
        model = context.model or self.model
        return 40, 450 if model is DeviceModel.G45 else 300

    def _validate_flow(self, flow: int, context: CommandContext) -> None:
        minimum, maximum = self._flow_range(context)
        if not minimum <= flow <= maximum or flow % 5:
            raise InvalidCommandError(
                f"airflow must be {minimum}..{maximum} m3/h in steps of 5"
            )

    def _is_g30_state(self, data_area: bytes) -> bool:
        return len(data_area) >= 29

    @staticmethod
    def _is_x50_state(data_area: bytes) -> bool:
        # The documented state data reaches linkage at offset 29.  A four-byte
        # 03/cmd/value/zero body is instead a checked command ACK.
        return len(data_area) >= 30

    def _decode_x50_state(
        self,
        identity: HeaderIdentity,
        sequence: int,
        inner_sequence: int | None,
        data_area: bytes,
        source: tuple[str, int],
        metadata: dict[str, int | bytes | str],
    ) -> DecodedPacket:
        packed = data_area[3]
        raw_speed = data_area[4]
        raw_timer = data_area[5]
        raw_lock = data_area[7]
        raw_display = data_area[8]
        raw_power = data_area[9]
        online_total_raw = int.from_bytes(data_area[19:21], "big")
        processed_exponent = data_area[21]
        processed_base = int.from_bytes(data_area[22:24], "big")
        purified_exponent = data_area[24]
        purified_base = int.from_bytes(data_area[25:27], "big")
        raw_values: dict[str, int] = {
            "mode_raw": packed & 0x0F,
            "speed_raw": raw_speed,
            "timer_hours_raw": raw_timer,
            "air_quality_raw": data_area[6],
            "child_lock_raw": raw_lock,
            "display_raw": raw_display,
            "power_raw": raw_power,
            "online_total_raw": online_total_raw,
            "linkage_raw": data_area[29],
        }
        child_lock = _f072_lock(raw_lock)
        display_on = _f072_on_off(raw_display)
        power = _f072_power(raw_power)
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
            # State-parser evidence includes speed 6 although the documented
            # X50 control table only permits speed values through 5.
            speed=raw_speed if 1 <= raw_speed <= 6 else None,
            timer_hours=raw_timer if raw_timer in {0, 1, 2, 3, 5, 8} else None,
            air_quality_raw=data_area[6],
            child_lock=child_lock,
            display_on=display_on,
            power=power,
            timer_remaining_minutes=int.from_bytes(data_area[10:12], "big"),
            pm25=int.from_bytes(data_area[12:14], "big"),
            processed_air_m3=processed_air,
            purified_air_m3=purified_air,
            processed_air_exponent=processed_exponent,
            processed_air_base=processed_base,
            purified_air_exponent=purified_exponent,
            purified_air_base=purified_base,
            linkage_raw=data_area[29],
            raw_values=raw_values,
        )
        return DecodedPacket(
            identity=identity,
            sequence=sequence,
            kind=PacketKind.STATE,
            state=state,
            source=source,
            family=self.family,
            inner_sequence=inner_sequence,
            raw_metadata=metadata,
        )

    def _decode_g30_state(
        self,
        identity: HeaderIdentity,
        sequence: int,
        inner_sequence: int | None,
        data_area: bytes,
        source: tuple[str, int],
        metadata: dict[str, int | bytes | str],
    ) -> DecodedPacket:
        packed = data_area[3]
        raw_timer = data_area[5]
        raw_lock = data_area[7]
        raw_display = data_area[8]
        raw_power = data_area[9]
        raw_ptc = data_area[18]
        raw_flow = int.from_bytes(data_area[27:29], "big")
        processed_exponent = data_area[21]
        processed_base = int.from_bytes(data_area[22:24], "big")
        purified_exponent = data_area[24]
        purified_base = int.from_bytes(data_area[25:27], "big")
        raw_values: dict[str, int] = {
            "mode_raw": packed & 0x0F,
            "timer_hours_raw": raw_timer,
            "air_quality_raw": data_area[6],
            "child_lock_raw": raw_lock,
            "display_raw": raw_display,
            "power_raw": raw_power,
            "ptc_raw": raw_ptc,
            "airflow_raw": raw_flow,
            "online_total_raw": int.from_bytes(data_area[19:21], "big"),
        }
        child_lock = _f072_lock(raw_lock)
        display_on = _f072_on_off(raw_display)
        power = _f072_power(raw_power)
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

        minimum, maximum = self._flow_range_for_decode()
        airflow = (
            raw_flow if minimum <= raw_flow <= maximum and raw_flow % 5 == 0 else None
        )
        if airflow is None:
            raw_values["airflow_unknown"] = raw_flow

        state = DeviceState(
            # G30/G45 evidence names only auto (1) and deep clean (5).  Do
            # not borrow X50/A5 labels for the other encoded values.
            mode=_g30_mode(packed & 0x0F),
            filter_type_raw=packed >> 4,
            timer_hours=raw_timer if raw_timer in {0, 1, 2, 3, 5, 8} else None,
            air_quality_raw=data_area[6],
            child_lock=child_lock,
            display_on=display_on,
            power=power,
            timer_remaining_minutes=int.from_bytes(data_area[10:12], "big"),
            pm25=int.from_bytes(data_area[12:14], "big"),
            processed_air_m3=processed_air,
            purified_air_m3=purified_air,
            processed_air_exponent=processed_exponent,
            processed_air_base=processed_base,
            purified_air_exponent=purified_exponent,
            purified_air_base=purified_base,
            temperature=data_area[14],
            humidity=data_area[15],
            co2=int.from_bytes(data_area[16:18], "big"),
            ptc=raw_ptc if raw_ptc in {0, 1, 2} else None,
            airflow_m3h=airflow,
            raw_values=raw_values,
        )
        return DecodedPacket(
            identity=identity,
            sequence=sequence,
            kind=PacketKind.STATE,
            state=state,
            source=source,
            family=self.family,
            inner_sequence=inner_sequence,
            raw_metadata=metadata,
        )

    def _flow_range_for_decode(self) -> tuple[int, int]:
        return 40, 450 if self.model is DeviceModel.G45 else 300

    def _check_identity(self, identity: HeaderIdentity) -> None:
        if identity.wire_type != self._wire_type:
            raise InvalidCommandError(
                f"{self.family.value} requires a learned wire type of {self._wire_type}"
            )


class F072X50Codec(F072Codec):
    """Convenience concrete codec for X50/X50S/X60/X70."""

    def __init__(self, model: DeviceModel | None = None) -> None:
        super().__init__(ProtocolFamily.F072_X50, model)


class F072G30Codec(F072Codec):
    """Convenience concrete codec for G30/G45."""

    def __init__(self, model: DeviceModel | None = None) -> None:
        super().__init__(ProtocolFamily.F072_G30, model)


def _single_value_frame(
    inner_type: int, inner_sequence: int, command: int, value: int
) -> bytes:
    frame_without_crc = (
        _PREFIX
        + b"\x00\x0d"
        + bytes((inner_type, 0x04, 0x02))
        + inner_sequence.to_bytes(2, "big")
        + bytes((0x03, command, value, 0x00))
    )
    return frame_without_crc + crc16_genibus(frame_without_crc[2:]).to_bytes(2, "big")


def _flow_frame(inner_type: int, inner_sequence: int, flow: int) -> bytes:
    frame_without_crc = (
        _PREFIX
        + b"\x00\x0d"
        + bytes((inner_type, 0x04, 0x02))
        + inner_sequence.to_bytes(2, "big")
        + bytes((0x03, 0x58))
        + flow.to_bytes(2, "big")
    )
    return frame_without_crc + crc16_genibus(frame_without_crc[2:]).to_bytes(2, "big")


def _validate_single_value(family: ProtocolFamily, command: Command) -> None:
    values: dict[CommandOperation, set[int]] = {
        CommandOperation.MODE: {1, 2, 3, 5}
        if family is ProtocolFamily.F072_X50
        else {1, 5},
        CommandOperation.SPEED: {0, 1, 2, 3, 4, 5},
        CommandOperation.PTC: {0, 1, 2},
        CommandOperation.TIMER: {0, 1, 2, 3, 5, 8},
        CommandOperation.CHILD_LOCK: {0x00, 0x11},
        CommandOperation.DISPLAY: {0x00, 0x11},
        CommandOperation.POWER: {0x00, 0x11},
    }
    if command.value not in values[command.operation]:
        raise InvalidCommandError(
            f"invalid {family.value} value {command.value:#x} "
            f"for {command.operation.value}"
        )


def _f072_lock(value: int) -> bool | None:
    if value == 0x00:
        return True
    if value == 0x11:
        return False
    return None


def _f072_on_off(value: int) -> bool | None:
    if value == 0x00:
        return True
    if value == 0x11:
        return False
    return None


def _f072_power(value: int) -> PowerState | None:
    if value == 0x00:
        return PowerState.ON
    if value == 0x11:
        return PowerState.OFF
    return None


def _g30_mode(value: int) -> ModeValue:
    """Preserve G30/G45 values lacking a documented semantic label."""

    return known_mode(value) if value in {1, 5} else value


def _safe_cumulative_volume(base: int, exponent: int) -> int | None:
    """Retain raw high exponents without publishing impractical numeric values."""

    # The same encoded counter used by captured X83C hardware reaches exponent
    # 4 even though the retired app's parser branches only through 3.
    if not 0 <= exponent <= 4:
        return None
    return base * (1, 10, 100, 1000, 10000)[exponent]
