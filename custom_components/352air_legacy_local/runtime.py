# SPDX-License-Identifier: GPL-3.0-or-later
"""Home Assistant runtime bridge for a single local 352 device."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
from time import monotonic
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    AVAILABILITY_CHECK_SECONDS,
    AVAILABILITY_TIMEOUT_SECONDS,
    CONF_AUTH,
    CONF_COMPANY,
    CONF_HOST,
    CONF_MAC,
    CONF_MODEL,
    CONF_WIRE_TYPE,
    DOMAIN,
    MODEL_OPTIONS,
    mac_to_bytes,
    normalize_mac,
)

# Protocol imports are deliberately contained in this one module. The parallel
# protocol implementation supplies these pure values and transport facade.
from .models import Command, CommandOperation, DeviceModel, DeviceState, HeaderIdentity
from .transport import LocalDeviceClient

if TYPE_CHECKING:
    from . import ConfigEntry

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RuntimeData:
    """Live, typed data attached to one Home Assistant config entry."""

    hass: HomeAssistant
    entry: ConfigEntry
    client: LocalDeviceClient
    model: str
    mac: str
    state: DeviceState | None
    available: bool
    last_seen: float
    last_error: str | None = None
    _remove_client_listener: Callable[[], None] | None = None
    _remove_identity_listener: Callable[[], None] | None = None
    _remove_staleness_listener: Callable[[], None] | None = None
    _state_listeners: set[Callable[[], None]] | None = None
    _refresh_task: asyncio.Task[None] | None = None

    def __post_init__(self) -> None:
        self._state_listeners = set()

    @property
    def device_info(self) -> DeviceInfo:
        """Build the one shared HA device descriptor."""
        return DeviceInfo(
            identifiers={(DOMAIN, self.mac)},
            manufacturer="352",
            model=MODEL_OPTIONS.get(self.model, self.model),
            name=f"352 Air {MODEL_OPTIONS.get(self.model, self.model)}",
        )

    @callback
    def async_add_state_listener(
        self, listener: Callable[[], None]
    ) -> Callable[[], None]:
        """Subscribe an entity to validated state changes."""
        assert self._state_listeners is not None
        self._state_listeners.add(listener)

        @callback
        def _remove() -> None:
            assert self._state_listeners is not None
            self._state_listeners.discard(listener)

        return _remove

    @callback
    def async_start_availability_watch(self) -> None:
        """Mark the device unavailable after state traffic has gone stale."""
        if self._remove_staleness_listener is not None:
            return
        self._remove_staleness_listener = async_track_time_interval(
            self.hass,
            self._async_check_staleness,
            timedelta(seconds=AVAILABILITY_CHECK_SECONDS),
        )

    @callback
    def _async_check_staleness(self, _now: datetime) -> None:
        if self._refresh_task is not None and not self._refresh_task.done():
            return
        age = monotonic() - self.last_seen
        if age < AVAILABILITY_CHECK_SECONDS:
            return
        self._refresh_task = self.hass.async_create_task(
            self._async_refresh_stale_state(),
            "352air legacy local state refresh",
        )

    async def _async_refresh_stale_state(self) -> None:
        """Recover missed broadcasts without polling a recently seen device."""
        try:
            await self.client.refresh_if_stale(AVAILABILITY_CHECK_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.last_error = type(err).__name__
            if monotonic() - self.last_seen >= AVAILABILITY_TIMEOUT_SECONDS:
                self.available = False
                self._async_notify_listeners()

    @callback
    def _async_handle_state(self, state: DeviceState) -> None:
        """Accept a validated state pushed by the pure transport client."""
        self.state = state
        self.available = True
        self.last_error = None
        self.last_seen = monotonic()
        self._async_persist_learned_identity()
        self._async_notify_listeners()

    @callback
    def _async_notify_listeners(self) -> None:
        assert self._state_listeners is not None
        for listener in tuple(self._state_listeners):
            listener()

    @callback
    def _async_persist_learned_identity(
        self, _identity: HeaderIdentity | None = None
    ) -> None:
        """Persist updated non-secret wire header fields learned by the client."""
        identity = self.client.identity
        try:
            learned_mac = normalize_mac(identity.mac)
        except (AttributeError, TypeError, ValueError):
            return

        current_data = dict(self.entry.data)
        updates: dict[str, str | int] = {
            CONF_HOST: self.client.host,
            CONF_MAC: learned_mac,
            CONF_COMPANY: int(identity.company),
            CONF_WIRE_TYPE: int(identity.wire_type),
            CONF_AUTH: int(identity.auth),
        }
        if all(current_data.get(key) == value for key, value in updates.items()):
            return
        current_data.update(updates)
        self.hass.config_entries.async_update_entry(self.entry, data=current_data)

    async def async_command(self, operation: str, value: int | bool) -> DeviceState:
        """Send a logical command and require the client's confirmed state."""
        try:
            confirmed_state = await self.client.command(
                Command(
                    operation=CommandOperation(operation),
                    value=_wire_command_value(self.model, operation, value),
                )
            )
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.last_error = type(err).__name__
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="command_failed",
            ) from err
        return confirmed_state

    async def async_close(self) -> None:
        """Remove HA callbacks and close every resource owned by the client."""
        if self._remove_staleness_listener is not None:
            self._remove_staleness_listener()
            self._remove_staleness_listener = None
        if self._remove_client_listener is not None:
            self._remove_client_listener()
            self._remove_client_listener = None
        if self._remove_identity_listener is not None:
            self._remove_identity_listener()
            self._remove_identity_listener = None
        if self._refresh_task is not None and not self._refresh_task.done():
            self._refresh_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._refresh_task
        self._refresh_task = None
        await self.client.close()

    def diagnostics_snapshot(self) -> dict[str, Any]:
        """Return non-packet runtime detail for diagnostics redaction."""
        return {
            "model": self.model,
            "available": self.available,
            "last_error": self.last_error,
            "state": _diagnostic_value(self.state),
        }


def _diagnostic_value(value: Any) -> Any:
    """Serialize only safe scalar state data before diagnostics redaction."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        return f"<redacted bytes: {len(value)}>"
    if isinstance(value, Enum):
        return value.name
    if is_dataclass(value):
        return {
            field.name: _diagnostic_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _diagnostic_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list | set | frozenset):
        return [_diagnostic_value(item) for item in value]
    return str(value)


def _device_model(model: str) -> DeviceModel:
    """Convert persisted config data into the pure protocol model enum."""
    try:
        return DeviceModel[model]
    except KeyError:
        # The protocol enum is expected to use the persisted clean-room names;
        # retaining this explicit error makes an invalid entry actionable.
        raise ConfigEntryNotReady("Unsupported configured device model") from None


def _wire_command_value(model: str, operation: str, value: int | bool) -> int:
    """Translate HA logical booleans to the selected family's proven bytes."""
    if not isinstance(value, bool):
        return int(value)
    if operation == "display":
        return 0x00 if value else 0x11
    if operation == "child_lock":
        if model in {"X83", "X83C", "X83C_PLUS"}:
            return 0x11 if value else 0x00
        return 0x00 if value else 0x11
    if operation == "power":
        if model in {"X83", "X83C", "X83C_PLUS"}:
            return 0x35 if value else 0x11
        return 0x00 if value else 0x11
    return int(value)


def _header_identity(entry: ConfigEntry) -> HeaderIdentity:
    """Build a protocol identity from read-only discovery data."""
    try:
        return HeaderIdentity(
            mac=mac_to_bytes(entry.data[CONF_MAC]),
            company=int(entry.data[CONF_COMPANY]),
            wire_type=int(entry.data[CONF_WIRE_TYPE]),
            auth=int(entry.data[CONF_AUTH]),
        )
    except (KeyError, TypeError, ValueError) as err:
        raise ConfigEntryNotReady("Missing or invalid discovery identity") from err


async def async_create_runtime(hass: HomeAssistant, entry: ConfigEntry) -> RuntimeData:
    """Start the pure client, validate connectivity, and return typed runtime data."""
    try:
        client = LocalDeviceClient(
            host=str(entry.data[CONF_HOST]),
            identity=_header_identity(entry),
            model=_device_model(str(entry.data[CONF_MODEL])),
        )
        await client.start()
        state = await client.refresh()
    except asyncio.CancelledError:
        raise
    except Exception as err:
        if "client" in locals():
            await client.close()
        raise ConfigEntryNotReady("Unable to contact the local device") from err

    runtime = RuntimeData(
        hass=hass,
        entry=entry,
        client=client,
        model=str(entry.data[CONF_MODEL]),
        mac=normalize_mac(entry.data[CONF_MAC]),
        state=state,
        available=True,
        last_seen=monotonic(),
    )
    runtime._remove_client_listener = client.add_listener(runtime._async_handle_state)
    runtime._remove_identity_listener = client.add_identity_listener(
        runtime._async_persist_learned_identity
    )
    runtime._async_persist_learned_identity()
    runtime.async_start_availability_watch()
    return runtime
