# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed, Home-Assistant-independent values for the local 352 protocol.

The types in this module deliberately describe only values that are available
from a validated local packet.  They do not make cloud-derived claims about a
filter, device health, or a retail model that the device has not confirmed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Final


class DeviceModel(StrEnum):
    """Models known to the clean-room integration."""

    M25 = "m25"
    X83 = "x83"
    G30 = "g30"
    X83C = "x83c"
    X50 = "x50"
    X50S = "x50s"
    X83C_PLUS = "x83c_plus"
    X60 = "x60"
    X70 = "x70"
    G45 = "g45"


class ProtocolFamily(StrEnum):
    """Inner wire families, rather than a claimed retail model."""

    M25 = "m25"
    A5A0 = "a5a0"
    F072_X50 = "f072_x50"
    F072_G30 = "f072_g30"


MODEL_FAMILIES: Final[Mapping[DeviceModel, ProtocolFamily]] = MappingProxyType(
    {
        DeviceModel.M25: ProtocolFamily.M25,
        DeviceModel.X83: ProtocolFamily.A5A0,
        DeviceModel.X83C: ProtocolFamily.A5A0,
        DeviceModel.X83C_PLUS: ProtocolFamily.A5A0,
        DeviceModel.X50: ProtocolFamily.F072_X50,
        DeviceModel.X50S: ProtocolFamily.F072_X50,
        DeviceModel.X60: ProtocolFamily.F072_X50,
        DeviceModel.X70: ProtocolFamily.F072_X50,
        DeviceModel.G30: ProtocolFamily.F072_G30,
        DeviceModel.G45: ProtocolFamily.F072_G30,
    }
)


def family_for_model(model: DeviceModel) -> ProtocolFamily:
    """Return the supported local wire family for *model*."""

    return MODEL_FAMILIES[model]


class PowerState(StrEnum):
    """A power state whose wire representation has been decoded."""

    OFF = "off"
    ON = "on"


class OperatingMode(int, Enum):
    """Known values used by the purifier protocol families.

    A decoder uses this enum only for these values.  Other values are kept as
    integers in :attr:`DeviceState.mode`.
    """

    AUTO = 1
    SLEEP = 2
    TURBO = 3
    MANUAL = 4
    DEEP_CLEAN = 5


type ModeValue = OperatingMode | int


class PacketKind(StrEnum):
    """The useful class of a validated inbound packet."""

    STATE = "state"
    ACK = "ack"
    DISCOVERY = "discovery"
    BACKLIGHT = "backlight"


class CommandOperation(StrEnum):
    """Operations whose documented local wire representation is known."""

    MODE = "mode"
    SPEED = "speed"
    PTC = "ptc"
    TIMER = "timer"
    CHILD_LOCK = "child_lock"
    DISPLAY = "display"
    FILTER_OPERATION = "filter_operation"
    POWER = "power"
    AIRFLOW = "airflow"
    PERCENTAGE = "percentage"
    BACKLIGHT = "backlight"


@dataclass(frozen=True, slots=True)
class HeaderIdentity:
    """Header values learned from a single device's outer UDP packets."""

    mac: bytes
    company: int
    wire_type: int
    auth: int

    def __post_init__(self) -> None:
        mac = bytes(self.mac)
        if len(mac) != 6:
            raise ValueError("MAC address must contain exactly six bytes")
        object.__setattr__(self, "mac", mac)
        _check_unsigned("company", self.company, 8)
        _check_unsigned("wire_type", self.wire_type, 8)
        _check_unsigned("auth", self.auth, 16)

    @property
    def normalized_mac(self) -> str:
        """Return the stable, lower-case colon-separated identity key."""

        return self.mac.hex(":")


@dataclass(frozen=True, slots=True)
class Command:
    """A command with a protocol value, not an optimistic resulting state.

    ``value`` is the documented wire value for ``operation``.  The one
    exception is :attr:`CommandOperation.PERCENTAGE`, whose value is the
    Home-Assistant-facing 0..100 percentage convention and which the G30
    codec converts to either power-off or a stepped airflow command.
    """

    operation: CommandOperation
    value: int

    def __post_init__(self) -> None:
        if not isinstance(self.operation, CommandOperation):
            object.__setattr__(self, "operation", CommandOperation(self.operation))
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise TypeError("command value must be an integer")
        if not 0 <= self.value <= 0xFFFF:
            raise ValueError("command value must fit in an unsigned 16-bit field")

    @classmethod
    def percentage(cls, value: int) -> Command:
        """Build the integration's G30/G45 0..100 percentage command."""

        if not 0 <= value <= 100:
            raise ValueError("percentage must be in the range 0..100")
        return cls(CommandOperation.PERCENTAGE, value)

    @property
    def is_coalescible(self) -> bool:
        """Whether replacing an as-yet-unsent command is safe."""

        return self.operation in {
            CommandOperation.PERCENTAGE,
            CommandOperation.SPEED,
        }


@dataclass(frozen=True, slots=True)
class CommandContext:
    """All mutable wire counters supplied explicitly to a deterministic codec."""

    identity: HeaderIdentity
    outer_sequence: int
    inner_sequence: int = 0
    model: DeviceModel | None = None
    outer_operation: int = 0x04

    def __post_init__(self) -> None:
        _check_unsigned("outer_sequence", self.outer_sequence, 16)
        _check_unsigned("inner_sequence", self.inner_sequence, 16)
        _check_unsigned("outer_operation", self.outer_operation, 8)


def _freeze_raw_values(
    values: Mapping[str, int | bytes | str],
) -> Mapping[str, int | bytes | str]:
    """Copy caller-owned diagnostics so a frozen state remains immutable."""

    return MappingProxyType(dict(values))


@dataclass(frozen=True, slots=True)
class DeviceState:
    """Validated local observations for one device.

    Optional fields are omitted when the respective response family has not
    documented their position or when a packet supplies an unknown value.  Raw
    values are intentionally retained for diagnostics without assigning labels
    that the protocol evidence does not support.
    """

    mode: ModeValue | None = None
    speed: int | None = None
    timer_hours: int | None = None
    timer_remaining_minutes: int | None = None
    air_quality_raw: int | None = None
    child_lock: bool | None = None
    display_on: bool | None = None
    power: PowerState | None = None
    ptc: int | None = None
    pm25: int | None = None
    filter_type_raw: int | None = None
    processed_air_m3: int | None = None
    purified_air_m3: int | None = None
    processed_air_exponent: int | None = None
    processed_air_base: int | None = None
    purified_air_exponent: int | None = None
    purified_air_base: int | None = None
    temperature: int | None = None
    humidity: int | None = None
    co2: int | None = None
    airflow_m3h: int | None = None
    linkage_raw: int | None = None
    backlight: int | None = None
    raw_values: Mapping[str, int | bytes | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw_values", _freeze_raw_values(self.raw_values))

    # These aliases are the concise names consumed by the HA-facing runtime.
    # The canonical field names make their unit/raw nature unambiguous here.
    @property
    def display(self) -> bool | None:
        return self.display_on

    @property
    def timer_remaining(self) -> int | None:
        return self.timer_remaining_minutes

    @property
    def air_quality(self) -> int | None:
        return self.air_quality_raw

    @property
    def processed_air(self) -> int | None:
        return self.processed_air_m3

    @property
    def purified_air(self) -> int | None:
        return self.purified_air_m3

    @property
    def airflow(self) -> int | None:
        return self.airflow_m3h


type Endpoint = tuple[str, int]


@dataclass(frozen=True, slots=True)
class DecodedPacket:
    """A fully bounds-checked packet exposed by a family codec."""

    identity: HeaderIdentity
    sequence: int
    kind: PacketKind
    state: DeviceState | None
    source: Endpoint
    family: ProtocolFamily
    inner_sequence: int | None = None
    raw_metadata: Mapping[str, int | bytes | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _check_unsigned("sequence", self.sequence, 16)
        if self.inner_sequence is not None:
            _check_unsigned("inner_sequence", self.inner_sequence, 16)
        object.__setattr__(self, "raw_metadata", _freeze_raw_values(self.raw_metadata))


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """A read-only discovery reply whose embedded address was validated."""

    identity: HeaderIdentity
    host: str
    source: Endpoint
    sequence: int


class LocalProtocolError(Exception):
    """Base exception for local protocol and transport failures."""


class InvalidCommandError(LocalProtocolError, ValueError):
    """Raised before a command with no documented representation is sent."""


class ClientClosedError(LocalProtocolError):
    """Raised when a pending operation is interrupted by client shutdown."""


class RequestTimeoutError(LocalProtocolError, TimeoutError):
    """Raised when no validated, matching state arrives in time."""


class DeviceUnavailableError(LocalProtocolError, ConnectionError):
    """Raised when the UDP endpoint cannot be started or used."""


def known_mode(value: int) -> ModeValue:
    """Map documented mode values while retaining every unknown integer."""

    try:
        return OperatingMode(value)
    except ValueError:
        return value


def _check_unsigned(name: str, value: int, bits: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must fit in an unsigned {bits}-bit field")
