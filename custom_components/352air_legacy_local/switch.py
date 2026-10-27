# SPDX-License-Identifier: GPL-3.0-or-later
"""Local boolean controls supported by purifier protocol families."""

from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import ConfigEntry
from .const import model_is_purifier
from .entity import LegacyEntity, logical_bool, state_attribute
from .local_runtime import LocalDiscoveryRuntime
from .runtime import RuntimeData

_CHILD_LOCK = SwitchEntityDescription(
    key="child_lock",
    translation_key="child_lock",
    icon="mdi:account-lock-outline",
    entity_category=EntityCategory.CONFIG,
)


async def async_setup_entry(
    _hass: Any,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add only documented purifier controls, never inferred M25 controls."""
    if isinstance(entry.runtime_data, LocalDiscoveryRuntime):
        if entry.runtime_data.power_client is not None:
            async_add_entities([ExperimentalLifePower(entry.runtime_data)])
    elif model_is_purifier(entry.runtime_data.model):
        async_add_entities([ChildLockSwitch(entry.runtime_data)])


class ExperimentalLifePower(SwitchEntity):
    """An opt-in X83C Plus power switch, available only after a real read."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_translation_key = "experimental_life_power"

    def __init__(self, runtime: LocalDiscoveryRuntime) -> None:
        self._runtime = runtime
        self._attr_unique_id = f"{runtime.identity.unique_id}_experimental_power"

    @property
    def device_info(self):
        return self._runtime.device_info

    @property
    def available(self) -> bool:
        return self._runtime.reachable and self._runtime.power_state is not None

    @property
    def is_on(self) -> bool | None:
        return self._runtime.power_state

    async def async_turn_on(self, **_kwargs: Any) -> None:
        await self._runtime.async_set_power(True)

    async def async_turn_off(self, **_kwargs: Any) -> None:
        await self._runtime.async_set_power(False)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            self._runtime.async_add_listener(self.async_write_ha_state)
        )


class _LegacySwitch(SwitchEntity, LegacyEntity):
    """Base for logical switch state translated by protocol family codecs."""

    entity_description: SwitchEntityDescription
    _state_attribute: str
    _operation: str

    def __init__(
        self, runtime: RuntimeData, description: SwitchEntityDescription
    ) -> None:
        LegacyEntity.__init__(self, runtime, description.key)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        """Return a normalized boolean and leave unknown raw states unavailable."""
        return logical_bool(state_attribute(self._runtime, self._state_attribute))

    async def async_turn_on(self, **_kwargs: Any) -> None:
        """Use a logical true command; family codecs encode the actual byte."""
        await self._runtime.async_command(self._operation, True)

    async def async_turn_off(self, **_kwargs: Any) -> None:
        """Use a logical false command; family codecs encode the actual byte."""
        await self._runtime.async_command(self._operation, False)


class ChildLockSwitch(_LegacySwitch):
    """Child lock control."""

    _state_attribute = "child_lock"
    _operation = "child_lock"

    def __init__(self, runtime: RuntimeData) -> None:
        super().__init__(runtime, _CHILD_LOCK)
