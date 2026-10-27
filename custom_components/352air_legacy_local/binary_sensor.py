# SPDX-License-Identifier: GPL-3.0-or-later
"""Local connection visibility for 352Life entries."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import LocalConfigEntry
from .local_runtime import LocalDiscoveryRuntime


async def async_setup_entry(
    _hass: HomeAssistant,
    entry: LocalConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Expose discovery reachability separately from experimental controls."""
    async_add_entities([LocalConnectionSensor(entry.runtime_data)])


class LocalConnectionSensor(BinarySensorEntity):
    """Connectivity means a matching read-only response, not control readiness."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_translation_key = "local_connection"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, runtime: LocalDiscoveryRuntime) -> None:
        self._runtime = runtime
        self._attr_unique_id = f"{runtime.identity.unique_id}_local_connection"

    @property
    def device_info(self) -> DeviceInfo:
        return self._runtime.device_info

    @property
    def is_on(self) -> bool:
        return self._runtime.reachable

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "connection_type": "local_discovery",
            "control_supported": False,
            "discovery_mechanism": self._runtime.identity.mechanism,
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            self._runtime.async_add_listener(self.async_write_ha_state)
        )
