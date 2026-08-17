# SPDX-License-Identifier: GPL-3.0-or-later
"""Privacy-preserving diagnostics for 352 Air Legacy Local."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import ConfigEntry
from .const import CONF_AUTH, CONF_HOST, CONF_MAC

_TO_REDACT = {
    CONF_HOST,
    CONF_MAC,
    CONF_AUTH,
    "auth_code",
    "authentication_code",
    "header",
    "identity",
    "identifier",
    "identifiers",
    "device_id",
    "source",
    "source_endpoint",
    "ip",
    "address",
    "raw",
    "raw_data",
    "raw_metadata",
    "raw_packet",
    "packet",
    "packet_bytes",
    "datagram",
    "bytes",
}


async def async_get_config_entry_diagnostics(
    _hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return useful state metadata without local addresses or packet material."""
    return async_redact_data(
        {
            "entry": dict(entry.data),
            "runtime": entry.runtime_data.diagnostics_snapshot(),
        },
        _TO_REDACT,
    )
