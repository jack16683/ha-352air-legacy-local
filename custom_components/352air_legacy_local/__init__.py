# SPDX-License-Identifier: GPL-3.0-or-later
"""352 Air Legacy Local integration setup and unload lifecycle."""

from __future__ import annotations

from typing import cast

from homeassistant.config_entries import ConfigEntry as HAConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import PLATFORMS
from .local_runtime import LocalDiscoveryRuntime, async_create_local_runtime
from .runtime import RuntimeData, async_create_runtime

type ConfigEntry = HAConfigEntry[RuntimeData]
type LocalConfigEntry = HAConfigEntry[LocalDiscoveryRuntime]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry | LocalConfigEntry
) -> bool:
    """Set up a device after a confirmed local read-only discovery."""
    if entry.data.get("connection_type") == "local_discovery":
        local_entry = cast(LocalConfigEntry, entry)
        local_entry.runtime_data = await async_create_local_runtime(hass, local_entry)
        platforms = (Platform.BINARY_SENSOR,)
    else:
        legacy_entry = cast(ConfigEntry, entry)
        legacy_entry.runtime_data = await async_create_runtime(hass, legacy_entry)
        platforms = PLATFORMS
    try:
        await hass.config_entries.async_forward_entry_setups(entry, platforms)
    except BaseException:
        await entry.runtime_data.async_close()
        raise
    return True


async def async_unload_entry(
    hass: HomeAssistant, entry: ConfigEntry | LocalConfigEntry
) -> bool:
    """Unload every entity first, then close the shared UDP client."""
    platforms = (
        (Platform.BINARY_SENSOR,)
        if entry.data.get("connection_type") == "local_discovery"
        else PLATFORMS
    )
    if not await hass.config_entries.async_unload_platforms(entry, platforms):
        return False
    await entry.runtime_data.async_close()
    return True
