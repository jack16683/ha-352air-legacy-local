# SPDX-License-Identifier: GPL-3.0-or-later
"""Presence monitoring and optional experimental X83C Plus control."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from time import monotonic
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN
from .local_discovery import async_discover_coap_devices, async_scan_interfaces
from .protocols.alcs_experimental import AlcsError, Credentials, ExperimentalPowerClient
from .protocols.coap_discovery import LocalIdentity

if TYPE_CHECKING:
    from . import LocalConfigEntry


@dataclass(slots=True)
class LocalDiscoveryRuntime:
    """A verified identity and reachability, never fabricated purifier state."""

    hass: HomeAssistant
    entry: LocalConfigEntry
    identity: LocalIdentity
    reachable: bool = False
    last_seen: float | None = None
    last_error: str | None = None
    _listeners: set[Callable[[], None]] = field(default_factory=set)
    _remove_timer: Callable[[], None] | None = None
    _refresh_task: asyncio.Task[None] | None = None
    _command_tasks: set[asyncio.Task[Any]] = field(default_factory=set)
    _closed: bool = False
    _last_network_scan: float = -300
    power_client: ExperimentalPowerClient | None = field(default=None, repr=False)
    power_state: bool | None = None

    @property
    def device_info(self) -> DeviceInfo:
        info = DeviceInfo(
            identifiers={(DOMAIN, self.identity.unique_id)},
            manufacturer="352",
            model=self.identity.name,
            name=f"352 {self.identity.name}",
            sw_version=self.identity.firmware,
        )
        if self.identity.mac is not None:
            info["connections"] = {(CONNECTION_NETWORK_MAC, self.identity.mac)}
        return info

    @callback
    def async_add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(listener)

        @callback
        def remove() -> None:
            self._listeners.discard(listener)

        return remove

    @callback
    def async_start(self) -> None:
        """Poll discovery and, when explicitly enabled, experimental power state."""
        if self._remove_timer is None:
            self._remove_timer = async_track_time_interval(
                self.hass, self._async_check, timedelta(seconds=60)
            )

    @callback
    def _async_check(self, _now: datetime) -> None:
        if self._closed or (
            self._refresh_task is not None and not self._refresh_task.done()
        ):
            return
        self._refresh_task = self.hass.async_create_task(
            self.async_refresh(), name="352Life local identity refresh"
        )

    async def async_refresh(self) -> None:
        """Require the same product/device identity, even after an address change."""
        if self._closed:
            return
        found = None
        try:
            interfaces = await async_scan_interfaces(self.hass)
            candidates = await async_discover_coap_devices(
                interfaces=interfaces,
                host=self.identity.host,
                response_timeout=4,
                required_identity=self.identity.unique_id,
            )
            found = next(
                (d for d in candidates if d.unique_id == self.identity.unique_id),
                None,
            )
            # Recover DHCP changes, but do not broadcast on every failed poll.
            if found is None and monotonic() - self._last_network_scan >= 300:
                self._last_network_scan = monotonic()
                candidates = await async_discover_coap_devices(
                    interfaces=interfaces,
                    response_timeout=6,
                    required_identity=self.identity.unique_id,
                    excluded_ids=frozenset(
                        # The targeted identity must not be excluded.
                        entry.unique_id
                        for entry in self.hass.config_entries.async_entries(DOMAIN)
                        if entry.unique_id
                        and entry.unique_id != self.identity.unique_id
                    ),
                )
                found = next(
                    (d for d in candidates if d.unique_id == self.identity.unique_id),
                    None,
                )
            self.last_error = None if found is not None else "no_local_response"
        except (OSError, ValueError):
            self.last_error = "local_probe_failed"
        if self._closed:
            return
        self.reachable = found is not None
        if found is not None:
            self.identity = replace(
                found,
                mac=found.mac or self.identity.mac,
                firmware=found.firmware or self.identity.firmware,
            )
            self.last_seen = monotonic()
            data = {**self.entry.data, **self.identity.as_entry_data()}
            if dict(self.entry.data) != data:
                self.hass.config_entries.async_update_entry(self.entry, data=data)
        if self.power_client is not None:
            try:
                await self.power_client.update_host(self.identity.host)
                self.power_state = await self.power_client.read() if found else None
            except (AlcsError, ValueError):
                self.power_state = None
        if self._closed:
            return
        for listener in tuple(self._listeners):
            listener()

    async def async_set_power(self, desired: bool) -> None:
        """Require a fresh, authenticated state confirmation for experimental writes."""
        if self._closed or self.power_client is None:
            raise HomeAssistantError("Experimental Life control is unavailable")
        self.power_state = None
        for listener in tuple(self._listeners):
            listener()
        task = asyncio.current_task()
        assert task is not None
        self._command_tasks.add(task)
        try:
            self.power_state = await self.power_client.set_power(desired)
        except AlcsError as error:
            self.power_state = None
            for listener in tuple(self._listeners):
                listener()
            raise HomeAssistantError(
                "Experimental Life power could not be confirmed"
            ) from error
        finally:
            self._command_tasks.discard(task)
        for listener in tuple(self._listeners):
            listener()

    async def async_close(self) -> None:
        self._closed = True
        if self._remove_timer is not None:
            self._remove_timer()
            self._remove_timer = None
        if self._refresh_task is not None and not self._refresh_task.done():
            self._refresh_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._refresh_task
        self._refresh_task = None
        for task in tuple(self._command_tasks):
            task.cancel()
        if self._command_tasks:
            await asyncio.gather(*tuple(self._command_tasks), return_exceptions=True)
        self._command_tasks.clear()
        self._listeners.clear()

    def diagnostics_snapshot(self) -> dict[str, Any]:
        return {
            "connection_type": "local_discovery",
            "discovery_mechanism": self.identity.mechanism,
            "model": self.identity.model,
            "local_reachable": self.reachable,
            "control_supported": False,
            "experimental_power_enabled": self.power_client is not None,
            "experimental_power_available": self.power_state is not None,
            "last_seen_seconds_ago": (
                None if self.last_seen is None else max(0, monotonic() - self.last_seen)
            ),
            "last_error": self.last_error,
        }


async def async_create_local_runtime(
    hass: HomeAssistant, entry: LocalConfigEntry
) -> LocalDiscoveryRuntime:
    """Verify saved identity again before setting up the read-only device."""
    data = entry.data
    identity = LocalIdentity(
        host=data["host"],
        product_key=data["product_key"],
        device_name=data["device_name"],
        mechanism=data["discovery_mechanism"],
        mac=data.get("mac"),
        firmware=data.get("firmware"),
    )
    runtime = LocalDiscoveryRuntime(hass, entry, identity)
    if data.get("experimental_life_control") is True:
        try:
            credentials = Credentials(
                identity.product_key,
                identity.device_name,
                data["life_access_key"],
                data["life_access_token"],
            )
            runtime.power_client = ExperimentalPowerClient(identity.host, credentials)
        except (KeyError, ValueError) as error:
            raise ConfigEntryNotReady(
                "Invalid experimental Life credentials"
            ) from error
    try:
        await runtime.async_refresh()
        if not runtime.reachable:
            raise ConfigEntryNotReady(
                "No response from the saved local device identity"
            )
        runtime.async_start()
    except BaseException:
        await runtime.async_close()
        raise
    return runtime
