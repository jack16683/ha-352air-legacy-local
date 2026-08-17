# SPDX-License-Identifier: GPL-3.0-or-later
"""One complete Home Assistant fan entity for each legacy purifier."""

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
from .airflow import current_airflow_m3h
from .const import (
    CONTINUOUS_AIRFLOW_MODELS,
    DOMAIN,
    FIVE_SPEED_MODELS,
    MODEL_G30,
    MODEL_G45,
    MODEL_X50,
    MODEL_X50S,
    MODEL_X60,
    MODEL_X70,
    MODEL_X83,
    MODEL_X83C,
    MODEL_X83C_PLUS,
    SIX_SPEED_MODELS,
    model_is_purifier,
)
from .entity import LegacyEntity, enum_value, logical_bool, state_attribute
from .runtime import RuntimeData

_A5A0_SPEEDS = [1, 2, 3, 4, 5, 6]
_X50_COMMAND_SPEEDS = [1, 2, 3, 4, 5]
_G30_AIRFLOW_RANGE = (40, 300)
_G45_AIRFLOW_RANGE = (40, 450)

_MANUAL_PRESET = "manual"
_MODE_OPTIONS_BY_MODEL: dict[str, dict[str, int]] = {
    # X83C mode 5 was rejected by the tested device. Manual mode is entered by
    # sending a speed command rather than an unsupported mode=4 command.
    MODEL_X83C: {"auto": 1, "manual": 4, "sleep": 2, "turbo": 3},
    # These siblings share the A5A0 command family. Deep clean is recovered
    # from the retired app but remains unverified on these exact retail models.
    MODEL_X83: {
        "auto": 1,
        "manual": 4,
        "sleep": 2,
        "turbo": 3,
        "deep_clean": 5,
    },
    MODEL_X83C_PLUS: {
        "auto": 1,
        "manual": 4,
        "sleep": 2,
        "turbo": 3,
        "deep_clean": 5,
    },
    # F072 uses speed/airflow to enter manual mode; mode=4 is not a documented
    # outbound command for this family.
    **{
        model: {
            "auto": 1,
            "manual": 4,
            "sleep": 2,
            "turbo": 3,
            "deep_clean": 5,
        }
        for model in (MODEL_X50, MODEL_X50S, MODEL_X60, MODEL_X70)
    },
    **{
        model: {"auto": 1, "manual": 4, "deep_clean": 5}
        for model in (MODEL_G30, MODEL_G45)
    },
}


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
    _attr_icon = "mdi:air-purifier"
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
    def extra_state_attributes(self) -> dict[str, int] | None:
        """Expose airflow without violating Home Assistant's percentage API."""
        attributes: dict[str, int] = {}
        speed = state_attribute(self._runtime, "speed")
        airflow = current_airflow_m3h(
            self._runtime.model,
            speed=speed,
            filter_profile=state_attribute(self._runtime, "filter_type_raw"),
            reported_airflow=state_attribute(self._runtime, "airflow"),
        )
        if airflow is not None:
            attributes["airflow_m3h"] = airflow
        return attributes or None

    @property
    def preset_modes(self) -> list[str]:
        """Expose every documented model mode through the main fan entity."""
        return list(self._mode_options)

    @property
    def preset_mode(self) -> str | None:
        """Report the current protocol mode as the fan's active preset."""
        if self.is_on is False:
            return None
        value = enum_value(state_attribute(self._runtime, "mode"))
        if isinstance(value, str):
            normalized = value.casefold().replace("-", "_").replace(" ", "_")
            return normalized if normalized in self._mode_options else None
        if isinstance(value, int):
            return next(
                (
                    preset
                    for preset, command_value in self._mode_options.items()
                    if command_value == value
                ),
                None,
            )
        return None

    @property
    def _mode_options(self) -> dict[str, int]:
        """Return the selected retail model's bounded mode mapping."""
        return _MODE_OPTIONS_BY_MODEL[self._runtime.model]

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
        """Apply a model mode, using airflow to enter real manual mode."""
        command_value = self._mode_options.get(preset_mode)
        if command_value is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="unsupported_preset",
            )
        if preset_mode == _MANUAL_PRESET:
            percentage = self.percentage
            if percentage is None or percentage <= 0:
                percentage = max(1, round(100 / self.speed_count))
            await self.async_set_percentage(percentage)
            return
        await self._runtime.async_command("mode", command_value)


def _ordered_speed_to_percentage(value: Any | None, speeds: list[int]) -> int | None:
    """Convert only a valid discrete speed; unknown values stay unknown."""
    if not isinstance(value, int) or value not in speeds:
        return None
    return ordered_list_item_to_percentage(speeds, value)
