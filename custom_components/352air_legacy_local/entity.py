# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared entity primitives backed by the typed config-entry runtime."""

from __future__ import annotations

from enum import Enum
from typing import Any

from homeassistant.core import callback
from homeassistant.helpers.entity import Entity

from .runtime import RuntimeData


def state_attribute(runtime: RuntimeData, attribute: str) -> Any | None:
    """Read an optional, already validated protocol state field."""
    state = runtime.state
    if state is None:
        return None
    return getattr(state, attribute, None)


def enum_value(value: Any | None) -> Any | None:
    """Return an enum's wire-independent value for display decisions."""
    if isinstance(value, Enum):
        return value.value
    return value


def logical_bool(value: Any | None) -> bool | None:
    """Interpret normalized protocol boolean fields without guessing unknowns."""
    value = enum_value(value)
    if isinstance(value, bool):
        return value
    if value == "on":
        return True
    if value == "off":
        return False
    return None


class LegacyEntity(Entity):
    """An entity that immediately follows validated state broadcasts."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, runtime: RuntimeData, key: str) -> None:
        self._runtime = runtime
        self._attr_unique_id = f"{runtime.mac.replace(':', '')}_{key}"
        self._attr_device_info = runtime.device_info

    @property
    def available(self) -> bool:
        """Return client availability, never performing I/O from a property."""
        return self._runtime.available and self._runtime.state is not None

    async def async_added_to_hass(self) -> None:
        """Subscribe after Home Assistant is ready to receive state writes."""
        self.async_on_remove(
            self._runtime.async_add_state_listener(self._handle_state_update)
        )

    @callback
    def _handle_state_update(self) -> None:
        self.async_write_ha_state()
