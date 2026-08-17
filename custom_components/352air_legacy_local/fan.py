# SPDX-License-Identifier: GPL-3.0-or-later
"""Air-purifier fan entities with compact HomeKit percentage control."""

from __future__ import annotations

from typing import Any

from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util.percentage import (
    ordered_list_item_to_percentage,
    percentage_to_ordered_list_item,
)

from . import ConfigEntry
from .const import (
    CONTINUOUS_AIRFLOW_MODELS,
    DOMAIN,
    FIVE_SPEED_MODELS,
    SIX_SPEED_MODELS,
    model_is_purifier,
)
from .entity import LegacyEntity, enum_value, logical_bool, state_attribute
from .runtime import RuntimeData

_A5A0_SPEEDS = [1, 2, 3, 4, 5, 6]
_X50_COMMAND_SPEEDS = [1, 2, 3, 4, 5]
_G30_AIRFLOW_RANGE = (40, 300)
_G45_AIRFLOW_RANGE = (40, 450)

_HOMEKIT_SAFE_PRESETS = {"auto": 1}


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the device's main purifier control, but never one for M25."""
    if model_is_purifier(entry.runtime_data.model):
        async_add_entities([LegacyPurifierFan(entry.runtime_data)])


class LegacyPurifierFan(FanEntity, LegacyEntity):
    """The device's one main feature: local purifier power, presets, and airflow."""

    # Home Assistant's main-feature convention is a null entity name. The fan
    # therefore inherits the translated device name without a redundant
    # "Purifier" suffix; every secondary entity uses a translated description.
    _attr_name = None
    _attr_supported_features = (
        FanEntityFeature.SET_SPEED
        | FanEntityFeature.PRESET_MODE
        | FanEntityFeature.TURN_ON
        | FanEntityFeature.TURN_OFF
    )

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, "purifier")

    @property
    def is_on(self) -> bool | None:
        """Return only a normalized protocol power value."""
        return logical_bool(state_attribute(self._runtime, "power"))

    @property
    def percentage(self) -> int | None:
        """Map native speed/airflow to HA's 0-100 percentage convention."""
        if self.is_on is False:
            return 0
        model = self._runtime.model
        if model in SIX_SPEED_MODELS:
            return _ordered_speed_to_percentage(
                state_attribute(self._runtime, "speed"), _A5A0_SPEEDS
            )
        if model in FIVE_SPEED_MODELS:
            speed = state_attribute(self._runtime, "speed")
            if speed == 6:
                return 100
            return _ordered_speed_to_percentage(speed, _X50_COMMAND_SPEEDS)
        if model in CONTINUOUS_AIRFLOW_MODELS:
            flow = state_attribute(self._runtime, "airflow")
            if not isinstance(flow, int):
                return None
            minimum, maximum = self._airflow_range
            if not minimum <= flow <= maximum:
                return None
            return round(1 + 99 * (flow - minimum) / (maximum - minimum))
        return None

    @property
    def speed_count(self) -> int:
        """Expose the physical speed count, while HA still receives percentages."""
        if self._runtime.model in SIX_SPEED_MODELS:
            return len(_A5A0_SPEEDS)
        if self._runtime.model in FIVE_SPEED_MODELS:
            return len(_X50_COMMAND_SPEEDS)
        return 100

    @property
    def preset_modes(self) -> list[str]:
        """List true automatic presets, excluding manual speed and off."""
        return list(_HOMEKIT_SAFE_PRESETS)

    @property
    def preset_mode(self) -> str | None:
        """Report a recognized automatic preset; manual state has no preset."""
        if self.is_on is False:
            return None
        value = enum_value(state_attribute(self._runtime, "mode"))
        if isinstance(value, str):
            normalized = value.casefold().replace("-", "_").replace(" ", "_")
            return normalized if normalized in _HOMEKIT_SAFE_PRESETS else None
        if isinstance(value, int):
            return next(
                (
                    preset
                    for preset, command_value in _HOMEKIT_SAFE_PRESETS.items()
                    if command_value == value
                ),
                None,
            )
        return None

    @property
    def _airflow_range(self) -> tuple[int, int]:
        return (
            _G45_AIRFLOW_RANGE if self._runtime.model == "G45" else _G30_AIRFLOW_RANGE
        )

    async def async_turn_on(
        self,
        percentage: int | None = None,
        preset_mode: str | None = None,
        **_kwargs: Any,
    ) -> None:
        """Turn on before applying an optional HA percentage or preset."""
        await self._runtime.async_command("power", True)
        if preset_mode is not None:
            await self.async_set_preset_mode(preset_mode)
        elif percentage is not None and percentage > 0:
            await self.async_set_percentage(percentage)

    async def async_turn_off(self, **_kwargs: Any) -> None:
        """Map Home Assistant's zero/off convention to logical device power."""
        await self._runtime.async_command("power", False)

    async def async_set_percentage(self, percentage: int) -> None:
        """Set a manual airflow percentage; zero is always a power-off request."""
        if percentage <= 0:
            await self.async_turn_off()
            return
        percentage = min(100, percentage)
        if self._runtime.model in SIX_SPEED_MODELS:
            await self._runtime.async_command(
                "speed", percentage_to_ordered_list_item(_A5A0_SPEEDS, percentage)
            )
            return
        if self._runtime.model in FIVE_SPEED_MODELS:
            await self._runtime.async_command(
                "speed",
                percentage_to_ordered_list_item(_X50_COMMAND_SPEEDS, percentage),
            )
            return
        await self._runtime.async_command("percentage", percentage)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Apply a supported automatic mode, never an invented manual/off preset."""
        command_value = _HOMEKIT_SAFE_PRESETS.get(preset_mode)
        if command_value is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_preset",
            )
        await self._runtime.async_command("mode", command_value)


def _ordered_speed_to_percentage(value: Any | None, speeds: list[int]) -> int | None:
    """Convert only a valid discrete speed; unknown values stay unknown."""
    if not isinstance(value, int) or value not in speeds:
        return None
    return ordered_list_item_to_percentage(speeds, value)
