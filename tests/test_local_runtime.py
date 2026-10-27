# SPDX-License-Identifier: GPL-3.0-or-later
"""Presence refresh, identity changes, and cleanup with small HA stand-ins."""

from __future__ import annotations

import asyncio
import importlib
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from test_discovery import coap, local

importlib.import_module("cryptography.hazmat.primitives.ciphers")
PACKAGE = "_local_runtime_tests_352"
root = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = ModuleType(PACKAGE)
package.__path__ = [str(root)]
constants = ModuleType(f"{PACKAGE}.const")
constants.DOMAIN = "352air_legacy_local"
core = ModuleType("homeassistant.core")
core.HomeAssistant = object
core.callback = lambda fn: fn
exceptions = ModuleType("homeassistant.exceptions")
exceptions.ConfigEntryNotReady = type("ConfigEntryNotReady", (Exception,), {})
exceptions.HomeAssistantError = type("HomeAssistantError", (Exception,), {})
protocols = ModuleType(f"{PACKAGE}.protocols")
protocols.__path__ = [str(root / "protocols")]
registry = ModuleType("homeassistant.helpers.device_registry")
registry.CONNECTION_NETWORK_MAC = "mac"
registry.DeviceInfo = dict
event = ModuleType("homeassistant.helpers.event")
event.async_track_time_interval = Mock(return_value=Mock())
with patch.dict(
    sys.modules,
    {
        PACKAGE: package,
        f"{PACKAGE}.const": constants,
        f"{PACKAGE}.local_discovery": local,
        f"{PACKAGE}.protocols": protocols,
        f"{PACKAGE}.protocols.coap_discovery": coap,
        "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers.device_registry": registry,
        "homeassistant.helpers.event": event,
    },
):
    runtime = importlib.import_module(f"{PACKAGE}.local_runtime")

IDENTITY = coap.LocalIdentity(
    "192.0.2.123",
    "a1TNKV3wr7I",
    "fixture-device",
    "device_info",
    "12:34:56:78:9a:bc",
    "fixture-fw",
)


def environment():
    entry = SimpleNamespace(data=IDENTITY.as_entry_data(), unique_id=IDENTITY.unique_id)

    def update(e, *, data):
        e.data = data

    hass = SimpleNamespace(
        async_create_task=asyncio.create_task,
        config_entries=SimpleNamespace(
            async_entries=lambda _domain: [entry],
            async_update_entry=Mock(side_effect=update),
        ),
    )
    return hass, entry


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        p = patch.object(runtime, "async_scan_interfaces", AsyncMock(return_value=()))
        p.start()
        self.addCleanup(p.stop)

    async def test_setup_requires_an_actual_matching_reply(self):
        hass, entry = environment()
        with (
            patch.object(
                runtime, "async_discover_coap_devices", AsyncMock(return_value=())
            ),
            patch.object(runtime, "async_track_time_interval") as timer,
            self.assertRaises(exceptions.ConfigEntryNotReady),
        ):
            await runtime.async_create_local_runtime(hass, entry)
        timer.assert_not_called()
        hass.config_entries.async_update_entry.assert_not_called()

    async def test_setup_reachable_read_only_diagnostics_and_timer_removed(self):
        hass, entry = environment()
        remove_timer = Mock()
        with (
            patch.object(
                runtime,
                "async_discover_coap_devices",
                AsyncMock(return_value=(IDENTITY,)),
            ) as probe,
            patch.object(
                runtime, "async_track_time_interval", return_value=remove_timer
            ) as timer,
        ):
            instance = await runtime.async_create_local_runtime(hass, entry)
            self.assertTrue(instance.reachable)
            self.assertFalse(instance.diagnostics_snapshot()["control_supported"])
            self.assertEqual(instance.device_info["model"], "X83C Plus")
            self.assertEqual(
                probe.await_args.kwargs["required_identity"], IDENTITY.unique_id
            )
            instance.async_start()
            self.assertEqual(timer.call_count, 1)
            await instance.async_close()
        remove_timer.assert_called_once()

    async def test_wrong_identity_is_not_online_and_never_updates_entry(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY, reachable=True)
        other = coap.LocalIdentity(IDENTITY.host, IDENTITY.product_key, "other", "alcs")
        listener = Mock()
        instance.async_add_listener(listener)
        with patch.object(
            runtime, "async_discover_coap_devices", AsyncMock(return_value=(other,))
        ):
            await instance.async_refresh()
        self.assertFalse(instance.reachable)
        self.assertEqual(instance.last_error, "no_local_response")
        hass.config_entries.async_update_entry.assert_not_called()
        listener.assert_called_once()

    async def test_dhcp_recovery_requires_same_product_and_name(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        moved = coap.LocalIdentity(
            "192.0.2.124", IDENTITY.product_key, IDENTITY.device_name, "alcs"
        )
        with patch.object(
            runtime,
            "async_discover_coap_devices",
            AsyncMock(side_effect=[(), (moved,)]),
        ) as probe:
            await instance.async_refresh()
        self.assertTrue(instance.reachable)
        self.assertEqual(entry.data["host"], "192.0.2.124")
        self.assertEqual(entry.data["mac"], IDENTITY.mac)
        self.assertEqual(entry.data["firmware"], IDENTITY.firmware)
        self.assertNotIn("host", probe.await_args_list[1].kwargs)
        self.assertEqual(
            probe.await_args_list[1].kwargs["required_identity"], IDENTITY.unique_id
        )

    async def test_experimental_credentials_survive_identity_refresh(self):
        hass, entry = environment()
        entry.data.update(
            experimental_life_control=True,
            life_access_key="fixture-key",
            life_access_token="fixture-token",
        )
        changed = coap.LocalIdentity(
            "192.0.2.124", IDENTITY.product_key, IDENTITY.device_name, "alcs"
        )
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        instance.power_client = SimpleNamespace(
            update_host=AsyncMock(), read=AsyncMock(return_value=True)
        )
        with patch.object(
            runtime,
            "async_discover_coap_devices",
            AsyncMock(return_value=(changed,)),
        ):
            await instance.async_refresh()
        self.assertTrue(instance.power_state)
        self.assertEqual(entry.data["life_access_token"], "fixture-token")
        instance.power_client.update_host.assert_awaited_once_with("192.0.2.124")
        self.assertNotIn("fixture-token", str(instance.diagnostics_snapshot()))

    async def test_experimental_failed_write_never_keeps_optimistic_state(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        instance.power_state = False
        instance.power_client = SimpleNamespace(
            set_power=AsyncMock(side_effect=runtime.AlcsError("failed"))
        )
        with self.assertRaises(exceptions.HomeAssistantError):
            await instance.async_set_power(True)
        self.assertIsNone(instance.power_state)

    async def test_unload_cancels_inflight_experimental_command(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        started = asyncio.Event()

        async def write(_desired):
            started.set()
            await asyncio.Event().wait()

        instance.power_client = SimpleNamespace(set_power=AsyncMock(side_effect=write))
        task = asyncio.create_task(instance.async_set_power(True))
        await asyncio.wait_for(started.wait(), 1)
        await instance.async_close()
        self.assertTrue(task.cancelled())
        self.assertIsNone(instance.power_state)
        with self.assertRaises(exceptions.HomeAssistantError):
            await instance.async_set_power(False)

    async def test_unreachable_scan_is_throttled_and_errors_are_fixed_labels(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        with patch.object(
            runtime, "async_discover_coap_devices", AsyncMock(return_value=())
        ) as probe:
            await instance.async_refresh()
            await instance.async_refresh()
        self.assertEqual(probe.await_count, 3)  # Unicast + scan, then unicast only.
        with patch.object(
            runtime,
            "async_discover_coap_devices",
            AsyncMock(side_effect=OSError("private address here")),
        ):
            await instance.async_refresh()
        self.assertEqual(instance.last_error, "local_probe_failed")
        self.assertNotIn("private", str(instance.diagnostics_snapshot()))

    async def test_unload_cancels_probe_and_no_future_network_or_callbacks(self):
        hass, entry = environment()
        instance = runtime.LocalDiscoveryRuntime(hass, entry, IDENTITY)
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def probe(**_kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        listener = Mock()
        instance.async_add_listener(listener)
        with patch.object(
            runtime, "async_discover_coap_devices", AsyncMock(side_effect=probe)
        ) as discover:
            instance._async_check(None)
            await asyncio.wait_for(started.wait(), 1)
            await instance.async_close()
            instance._async_check(None)
            await instance.async_refresh()
        self.assertTrue(cancelled.is_set())
        self.assertIsNone(instance._refresh_task)
        self.assertEqual(discover.await_count, 1)
        listener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
