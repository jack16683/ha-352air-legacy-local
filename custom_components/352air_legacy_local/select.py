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
    MODEL_M25,
    model_is_purifier,
)
from .entity import LegacyEntity, state_attribute
from .runtime import RuntimeData

_TIMER = SelectEntityDescription(
    key="timer",
    translation_key="timer",
    icon="mdi:timer-cog-outline",
    entity_category=EntityCategory.CONFIG,
)
_TIMER_OPTIONS = ["off", "1", "2", "3", "5", "8"]
_PTC = SelectEntityDescription(
    key="ptc",
    translation_key="ptc",
    icon="mdi:radiator",
    entity_category=EntityCategory.CONFIG,
)
_PTC_OPTIONS = {"off": 0, "level_1": 1, "level_2": 2}
_BACKLIGHT = SelectEntityDescription(
    key="backlight_mode",
    translation_key="backlight_mode",
    icon="mdi:brightness-6",
    entity_category=EntityCategory.CONFIG,
)
_BACKLIGHT_OPTIONS = {"five_minutes": 0, "always_on": 1}


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the documented discrete shutoff-timer setting to purifier models."""
    runtime = entry.runtime_data
    entities: list[SelectEntity] = []
    if model_is_purifier(runtime.model):
        entities.append(TimerSelect(runtime))
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
