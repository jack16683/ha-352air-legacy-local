# SPDX-License-Identifier: GPL-3.0-or-later
"""Native selects for discrete local settings."""

from __future__ import annotations

from typing import Any

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import ConfigEntry
from .const import (
    CONTINUOUS_AIRFLOW_MODELS,
    DOMAIN,
    FIVE_SPEED_MODELS,
    MODEL_M25,
    MODEL_X83C,
    SIX_SPEED_MODELS,
    model_is_purifier,
)
from .entity import LegacyEntity, enum_value, state_attribute
from .runtime import RuntimeData

_TIMER = SelectEntityDescription(
    key="timer",
    translation_key="timer",
    entity_category=EntityCategory.CONFIG,
)
_TIMER_OPTIONS = ["off", "1", "2", "3", "5", "8"]
_PTC = SelectEntityDescription(
    key="ptc",
    translation_key="ptc",
    entity_category=EntityCategory.CONFIG,
)
_PTC_OPTIONS = {"off": 0, "level_1": 1, "level_2": 2}
_BACKLIGHT = SelectEntityDescription(
    key="backlight_mode",
    translation_key="backlight_mode",
    entity_category=EntityCategory.CONFIG,
)
_BACKLIGHT_OPTIONS = {"five_minutes": 0, "always_on": 1}
_MODE = SelectEntityDescription(key="operating_mode", translation_key="operating_mode")
_A5_MODE_OPTIONS = {"auto": 1, "sleep": 2, "turbo": 3, "deep_clean": 5}
_X83C_MODE_OPTIONS = {"auto": 1, "sleep": 2, "turbo": 3}
_X50_MODE_OPTIONS = {"auto": 1, "sleep": 2, "turbo": 3, "deep_clean": 5}
_G30_MODE_OPTIONS = {"auto": 1, "deep_clean": 5}


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the documented discrete shutoff-timer setting to purifier models."""
    runtime = entry.runtime_data
    entities: list[SelectEntity] = []
    if model_is_purifier(runtime.model):
        entities.extend((OperatingModeSelect(runtime), TimerSelect(runtime)))
    if runtime.model in CONTINUOUS_AIRFLOW_MODELS:
        entities.append(PtcSelect(runtime))
    if runtime.model == MODEL_M25:
        entities.append(BacklightSelect(runtime))
    async_add_entities(entities)


class TimerSelect(SelectEntity, LegacyEntity):
    """The selected shutoff duration, independent of remaining timer minutes."""

    entity_description = _TIMER
    _attr_options = _TIMER_OPTIONS

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, _TIMER.key)

    @property
    def current_option(self) -> str | None:
        """Report a known selected duration without coercing unknown state."""
        value = state_attribute(self._runtime, "timer_hours")
        if not isinstance(value, int):
            return None
        option = "off" if value == 0 else str(value)
        return option if option in self.options else None

    async def async_select_option(self, option: str) -> None:
        """Send the selected documented timer duration."""
        if option not in self.options:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_timer",
            )
        await self._runtime.async_command(
            "timer", 0 if option == "off" else int(option)
        )


class OperatingModeSelect(SelectEntity, LegacyEntity):
    """Full HA mode selector kept separate from compact HomeKit presets."""

    entity_description = _MODE

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, _MODE.key)
        if runtime.model == MODEL_X83C:
            self._option_values = _X83C_MODE_OPTIONS
        elif runtime.model in SIX_SPEED_MODELS:
            self._option_values = _A5_MODE_OPTIONS
        elif runtime.model in FIVE_SPEED_MODELS:
            self._option_values = _X50_MODE_OPTIONS
        else:
            self._option_values = _G30_MODE_OPTIONS
        self._attr_options = list(self._option_values)

    @property
    def current_option(self) -> str | None:
        value = enum_value(state_attribute(self._runtime, "mode"))
        if not isinstance(value, int):
            return None
        return next(
            (
                option
                for option, native in self._option_values.items()
                if native == value
            ),
            None,
        )

    async def async_select_option(self, option: str) -> None:
        if option not in self._option_values:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_option",
            )
        await self._runtime.async_command("mode", self._option_values[option])


class _MappedSelect(SelectEntity, LegacyEntity):
    """Select whose translated option key maps to a documented integer."""

    _state_attribute: str
    _operation: str
    _option_values: dict[str, int]

    @property
    def current_option(self) -> str | None:
        value = state_attribute(self._runtime, self._state_attribute)
        if not isinstance(value, int):
            return None
        return next(
            (
                option
                for option, native in self._option_values.items()
                if native == value
            ),
            None,
        )

    async def async_select_option(self, option: str) -> None:
        if option not in self._option_values:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_option",
            )
        await self._runtime.async_command(self._operation, self._option_values[option])


class PtcSelect(_MappedSelect):
    """G30/G45 PTC off/level control."""

    entity_description = _PTC
    _state_attribute = "ptc"
    _operation = "ptc"
    _option_values = _PTC_OPTIONS

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, _PTC.key)
        self._attr_options = list(_PTC_OPTIONS)


class BacklightSelect(_MappedSelect):
    """M25 five-minute or always-on backlight mode."""

    entity_description = _BACKLIGHT
    _state_attribute = "backlight"
    _operation = "backlight"
    _option_values = _BACKLIGHT_OPTIONS

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, _BACKLIGHT.key)
        self._attr_options = list(_BACKLIGHT_OPTIONS)
