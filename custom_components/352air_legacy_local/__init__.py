# SPDX-License-Identifier: GPL-3.0-or-later
"""352 Air Legacy Local integration setup and unload lifecycle."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry as HAConfigEntry
from homeassistant.core import HomeAssistant

from .const import PLATFORMS
from .runtime import RuntimeData, async_create_runtime

type ConfigEntry = HAConfigEntry[RuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a device after a confirmed local read-only discovery."""
    runtime = await async_create_runtime(hass, entry)
    entry.runtime_data = runtime
    try:
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        await runtime.async_close()
        raise
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload every entity first, then close the shared UDP client."""
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    await entry.runtime_data.async_close()
    return True
