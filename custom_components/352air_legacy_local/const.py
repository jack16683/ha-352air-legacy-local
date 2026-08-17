# SPDX-License-Identifier: GPL-3.0-or-later
"""Constants and model metadata for 352 Air Legacy Local."""

from __future__ import annotations

from collections.abc import Iterable

from homeassistant.const import Platform

DOMAIN = "352air_legacy_local"

CONF_HOST = "host"
CONF_MAC = "mac"
CONF_MODEL = "model"
CONF_COMPANY = "company"
CONF_WIRE_TYPE = "wire_type"
CONF_AUTH = "auth"

UDP_PORT = 11530
DISCOVERY_TIMEOUT_SECONDS = 4.0
AVAILABILITY_TIMEOUT_SECONDS = 120
AVAILABILITY_CHECK_SECONDS = 30

PLATFORMS: tuple[Platform, ...] = (
    Platform.FAN,
    Platform.SENSOR,
    Platform.LIGHT,
    Platform.SELECT,
    Platform.SWITCH,
)

MODEL_M25 = "M25"
MODEL_X83 = "X83"
MODEL_G30 = "G30"
MODEL_X83C = "X83C"
MODEL_X50 = "X50"
MODEL_X50S = "X50S"
MODEL_X83C_PLUS = "X83C_PLUS"
MODEL_X60 = "X60"
MODEL_X70 = "X70"
MODEL_G45 = "G45"

MODEL_OPTIONS: dict[str, str] = {
    MODEL_M25: "M25",
    MODEL_X83: "X83",
    MODEL_G30: "G30",
    MODEL_X83C: "X83C",
    MODEL_X50: "X50",
    MODEL_X50S: "X50S",
    MODEL_X83C_PLUS: "X83C Plus",
    MODEL_X60: "X60",
    MODEL_X70: "X70",
    MODEL_G45: "G45",
}

MODEL_WIRE_TYPES: dict[str, tuple[int, ...]] = {
    MODEL_M25: (1,),
    MODEL_X83: (2,),
    MODEL_G30: (4,),
    MODEL_X83C: (2,),
    MODEL_X50: (3,),
    MODEL_X50S: (3,),
    MODEL_X83C_PLUS: (2,),
    MODEL_X60: (3,),
    MODEL_X70: (3,),
    MODEL_G45: (4,),
}

MODELS_BY_WIRE_TYPE: dict[int, tuple[str, ...]] = {
    wire_type: tuple(
        model
        for model, wire_types in MODEL_WIRE_TYPES.items()
        if wire_type in wire_types
    )
    for wire_type in range(1, 5)
}

PURIFIER_MODELS = frozenset(MODEL_OPTIONS) - {MODEL_M25}
SIX_SPEED_MODELS = frozenset({MODEL_X83, MODEL_X83C, MODEL_X83C_PLUS})
FIVE_SPEED_MODELS = frozenset({MODEL_X50, MODEL_X50S, MODEL_X60, MODEL_X70})
CONTINUOUS_AIRFLOW_MODELS = frozenset({MODEL_G30, MODEL_G45})


def normalize_mac(value: str | bytes) -> str:
    """Return a canonical colon-separated MAC address, or raise ValueError."""
    if isinstance(value, bytes):
        if len(value) != 6:
            raise ValueError("A MAC address must contain six bytes")
        return ":".join(f"{byte:02x}" for byte in value)

    compact = value.strip().lower().replace(":", "").replace("-", "")
    if len(compact) != 12 or any(char not in "0123456789abcdef" for char in compact):
        raise ValueError("Invalid MAC address")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def mac_to_bytes(value: str | bytes) -> bytes:
    """Convert a normalized or user-entered MAC address to six bytes."""
    return bytes.fromhex(normalize_mac(value).replace(":", ""))


def model_is_purifier(model: str) -> bool:
    """Return whether the selected model is a purifier rather than the M25 detector."""
    return model in PURIFIER_MODELS


def compatible_models(
    wire_type: int, candidates: Iterable[str] | None = None
) -> tuple[str, ...]:
    """Return user-selectable models that can use a discovered wire family."""
    available = MODELS_BY_WIRE_TYPE.get(wire_type, ())
    if candidates is None:
        return available
    requested = set(candidates)
    return tuple(model for model in available if model in requested)
