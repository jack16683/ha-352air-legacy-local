# SPDX-License-Identifier: GPL-3.0-or-later
"""Display-light control for purifier models that advertise it."""

from __future__ import annotations

from typing import Any

from homeassistant.components.light import (
    ColorMode,
    LightEntity,
    LightEntityDescription,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import ConfigEntry
from .const import model_is_purifier
from .entity import LegacyEntity, logical_bool, state_attribute
from .runtime import RuntimeData

_DISPLAY_LIGHT = LightEntityDescription(
    key="display_light",
    translation_key="display_light",
)


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the display light for purifiers; the M25 is intentionally excluded."""
    if model_is_purifier(entry.runtime_data.model):
        async_add_entities([DisplayLight(entry.runtime_data)])


class DisplayLight(LightEntity, LegacyEntity):
    """The physical display/backlight as an on/off light entity."""

    entity_description = _DISPLAY_LIGHT
    _attr_color_mode = ColorMode.ONOFF

    def __init__(self, runtime: RuntimeData) -> None:
        LegacyEntity.__init__(self, runtime, _DISPLAY_LIGHT.key)
        self._attr_supported_color_modes = {ColorMode.ONOFF}

    @property
    def is_on(self) -> bool | None:
        """Return the protocol's normalized display state."""
        return logical_bool(state_attribute(self._runtime, "display"))

    async def async_turn_on(self, **_kwargs: Any) -> None:
        """Request display illumination with a logical value."""
        await self._runtime.async_command("display", True)

    async def async_turn_off(self, **_kwargs: Any) -> None:
        """Request display darkness with a logical value."""
        await self._runtime.async_command("display", False)
