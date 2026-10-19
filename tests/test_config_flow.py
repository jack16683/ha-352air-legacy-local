# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real schemas and flow validation with minimal HA UI stand-ins."""

from __future__ import annotations

import asyncio
import importlib
import sys
import unittest
from enum import StrEnum
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import voluptuous as vol


class _Selector:
    def __init__(self, *_args, **_kwargs):
        pass

    def __call__(self, value):
        return value


class _Flow:
    def __init_subclass__(cls, **_kwargs):
        pass

    def __init__(self):
        self.hass = SimpleNamespace(async_create_task=asyncio.create_task)
        self._progress_task = None

    async def async_set_unique_id(self, unique_id):
        self.unique_id = unique_id

    def _abort_if_unique_id_configured(self, **_kwargs):
        pass

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_show_menu(self, **kwargs):
        return {"type": "menu", **kwargs}

    def async_show_progress(self, **kwargs):
        self._progress_task = kwargs["progress_task"]
        return {"type": "progress", **kwargs}

    def async_show_progress_done(self, **kwargs):
        return {"type": "progress_done", **kwargs}

    def async_cancel_progress_task(self):
        if self._progress_task is not None:
            self._progress_task.cancel()
            self._progress_task = None

    def _async_current_entries(self):
        return []

    def async_create_entry(self, **kwargs):
        return {"type": "create_entry", **kwargs}

    def async_update_reload_and_abort(self, entry, **kwargs):
        return {"type": "update", "entry": entry, **kwargs}


PACKAGE = "_config_tests_352"
root = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = ModuleType(PACKAGE)
package.__path__ = [str(root)]
protocols = ModuleType(f"{PACKAGE}.protocols")
protocols.__path__ = [str(root / "protocols")]
ha = ModuleType("homeassistant")
ha.config_entries = SimpleNamespace(ConfigFlow=_Flow, ConfigEntry=object)
ha_const = ModuleType("homeassistant.const")
ha_const.Platform = StrEnum("Platform", "FAN SENSOR LIGHT SELECT SWITCH")
config_entries = ModuleType("homeassistant.config_entries")
config_entries.ConfigFlowResult = dict
helpers = ModuleType("homeassistant.helpers")
helpers.selector = SimpleNamespace(
    TextSelector=_Selector,
    TextSelectorConfig=dict,
    TextSelectorType=SimpleNamespace(PASSWORD="password"),
    BooleanSelector=_Selector,
)
dhcp = ModuleType("homeassistant.helpers.service_info.dhcp")
dhcp.DhcpServiceInfo = object
schedule = ModuleType(f"{PACKAGE}.schedule")
schedule.ScheduleCleanupError = type("ScheduleCleanupError", (Exception,), {})
schedule.async_clear_local_schedules = AsyncMock()
schedule.schedule_cleanup_supported = lambda wire_type: wire_type in {2, 3, 4}
with patch.dict(
    sys.modules,
    {
        PACKAGE: package,
        f"{PACKAGE}.protocols": protocols,
        f"{PACKAGE}.schedule": schedule,
        "homeassistant": ha,
        "homeassistant.const": ha_const,
        "homeassistant.config_entries": config_entries,
        "homeassistant.helpers": helpers,
        "homeassistant.helpers.service_info.dhcp": dhcp,
    },
):
    flow = importlib.import_module(f"{PACKAGE}.config_flow")

INPUT = {"host": "192.0.2.123", "mac": "12:34:56:78:9a:bc", "model": "X83C_PLUS"}
RESULT = flow.DiscoveryResult(INPUT["host"], INPUT["mac"], 0xF1, 2, 0xD3E7)


class SchemaTests(unittest.TestCase):
    def test_reconfigure_renders_stored_integer_auth_as_hex(self):
        schema = flow._full_schema({**INPUT, "auth": 0x0403, "company": 0xF1})
        values = schema(INPUT)
        self.assertEqual(values["auth"], "0403")
        self.assertEqual(values["company"], "F1")

    def test_empty_and_hex_encodings(self):
        for text, expected in (
            ("", None),
            ("   ", None),
            ("0", 0),
            ("0x0403", 0x0403),
            ("04 03", 0x0403),
            ("04:03", 0x0403),
            ("FFFF", 65535),
        ):
            with self.subTest(text=text):
                self.assertEqual(flow._parse_header_hex(text, 4), expected)
        for text in ("0x", "-1", "+12", "10000", "no", ":", True):
            with self.subTest(text=text), self.assertRaises(ValueError):
                flow._parse_header_hex(text, 4)

    def test_auth_remains_optional(self):
        values = flow._full_schema()(INPUT)
        self.assertEqual(values["auth"], "")
        self.assertEqual(values["company"], "")
        with self.assertRaises(vol.Invalid):
            flow._full_schema()({**INPUT, "model": "unknown"})


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def _finish_network_scan(self, config):
        progress = await config.async_step_auto()
        self.assertEqual(progress["type"], "progress")
        await asyncio.gather(progress["progress_task"], return_exceptions=True)
        done = await config.async_step_auto()
        self.assertEqual(done["type"], "progress_done")
        return await getattr(config, f"async_step_{done['next_step_id']}")()

    async def test_entry_menu_offers_auto_and_manual_without_network_io(self):
        config = flow.ConfigFlow()
        with (
            patch.object(flow, "async_discover_device", AsyncMock()) as target,
            patch.object(flow, "async_discover_devices", AsyncMock()) as network,
        ):
            result = await config.async_step_user()
        self.assertEqual(result["type"], "menu")
        self.assertEqual(result["menu_options"], ["auto", "manual"])
        target.assert_not_awaited()
        network.assert_not_awaited()

    async def test_manual_route_offers_every_model(self):
        config = flow.ConfigFlow()
        form = await config.async_step_manual()
        self.assertEqual(form["step_id"], "manual")
        for model in flow.MODEL_OPTIONS:
            with self.subTest(model=model):
                self.assertEqual(
                    form["data_schema"]({**INPUT, "model": model})["model"], model
                )

    async def test_dhcp_entry_also_offers_both_setup_methods(self):
        config = flow.ConfigFlow()
        info = SimpleNamespace(ip=INPUT["host"], macaddress=INPUT["mac"])
        with patch.object(
            flow, "async_discover_device", AsyncMock(return_value=RESULT)
        ):
            result = await config.async_step_dhcp(info)
        self.assertEqual(result["type"], "menu")
        self.assertEqual(result["menu_options"], ["auto", "manual"])
        manual = await config.async_step_manual()
        defaults = manual["data_schema"]({"model": "X50S"})
        self.assertEqual(defaults["host"], INPUT["host"])
        self.assertEqual(defaults["mac"], INPUT["mac"])
        self.assertEqual(defaults["auth"], "")
        self.assertEqual(defaults["company"], "")

    async def test_auto_uses_existing_dhcp_candidate_then_confirms_family(self):
        config = flow.ConfigFlow()
        config._pending_discovery = RESULT
        with patch.object(flow, "async_discover_devices", AsyncMock()) as network:
            result = await config.async_step_auto()
        network.assert_not_awaited()
        self.assertEqual(result["step_id"], "confirm_model")
        schema = result["data_schema"]
        for model in ("X83", "X83C", "X83C_PLUS"):
            self.assertEqual(schema({"model": model}), {"model": model})
        with self.assertRaises(vol.Invalid):
            schema({"model": "X50"})

    async def test_auto_scans_selects_device_and_saves_confirmed_model(self):
        config = flow.ConfigFlow()
        with patch.object(
            flow, "async_discover_devices", AsyncMock(return_value=(RESULT,))
        ):
            result = await self._finish_network_scan(config)
        self.assertEqual(result["step_id"], "select_device")
        self.assertEqual(
            result["data_schema"]({"device": RESULT.mac}), {"device": RESULT.mac}
        )
        confirm = await config.async_step_select_device({"device": RESULT.mac})
        self.assertEqual(confirm["step_id"], "confirm_model")
        self.assertEqual(config.unique_id, RESULT.mac)
        await config.async_step_confirm_model({"model": "X83C_PLUS"})
        entry = await config.async_step_schedule_cleanup(
            {"clear_local_schedules": False}
        )
        self.assertEqual(entry["data"]["model"], "X83C_PLUS")
        self.assertEqual(entry["data"]["auth"], RESULT.auth)

    async def test_auto_empty_failed_or_configured_results_offer_manual(self):
        for mode in ("empty", "failed", "configured"):
            with self.subTest(mode=mode):
                config = flow.ConfigFlow()
                config._async_current_entries = lambda: [
                    SimpleNamespace(unique_id=RESULT.mac)
                ]
                scan = AsyncMock(return_value=() if mode == "empty" else (RESULT,))
                if mode == "failed":
                    scan.side_effect = flow.DiscoveryError
                with patch.object(flow, "async_discover_devices", scan):
                    result = await self._finish_network_scan(config)
                scan.assert_awaited_once_with(excluded_macs=frozenset({RESULT.mac}))
                self.assertEqual(result["type"], "menu")
                self.assertEqual(result["step_id"], "no_devices")
                self.assertEqual(result["menu_options"], ["auto", "manual"])

    async def test_scan_progress_reuses_one_task_without_blocking_the_form(self):
        config = flow.ConfigFlow()
        completed = asyncio.Event()

        async def scan(**_kwargs):
            await completed.wait()
            return (RESULT,)

        with patch.object(
            flow, "async_discover_devices", AsyncMock(side_effect=scan)
        ) as discover:
            first = await config.async_step_auto()
            second = await config.async_step_auto()
            self.assertEqual(first["type"], "progress")
            self.assertEqual(first["description_placeholders"], {"seconds": "45"})
            self.assertIs(first["progress_task"], second["progress_task"])
            self.assertEqual(discover.call_count, 1)
            completed.set()
            await first["progress_task"]
            done = await config.async_step_auto()
        self.assertEqual(
            done, {"type": "progress_done", "next_step_id": "select_device"}
        )
        self.assertIsNone(config._discovery_task)

    async def test_closing_scan_progress_cancels_the_registered_task(self):
        config = flow.ConfigFlow()
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def scan(**_kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        with patch.object(flow, "async_discover_devices", AsyncMock(side_effect=scan)):
            progress = await config.async_step_auto()
            await asyncio.wait_for(started.wait(), timeout=1)
            config.async_cancel_progress_task()
            with self.assertRaises(asyncio.CancelledError):
                await progress["progress_task"]
        self.assertTrue(cancelled.is_set())

    async def test_stale_device_selection_does_not_create_entry(self):
        config = flow.ConfigFlow()
        config._discovered_devices = {RESULT.mac: RESULT}
        result = await config.async_step_select_device({"device": "unknown"})
        self.assertEqual(result["errors"], {"device": "invalid_device"})
        self.assertIsNone(config._pending_discovery)

    async def test_imported_credentials_used_for_probe_and_reply_saved(self):
        config = flow.ConfigFlow()
        discover = AsyncMock(return_value=RESULT)
        with patch.object(flow, "async_discover_device", discover):
            result = await config.async_step_user(
                {**INPUT, "auth": "12 34", "company": "F5"}
            )
        discover.assert_awaited_once_with(
            INPUT["host"],
            INPUT["mac"],
            (2,),
            auth=0x1234,
            company=0xF5,
            compatibility_probes=True,
        )
        self.assertEqual(result["step_id"], "schedule_cleanup")
        entry = await config.async_step_schedule_cleanup(
            {"clear_local_schedules": False}
        )
        self.assertEqual(entry["type"], "create_entry")
        self.assertEqual(entry["data"]["auth"], RESULT.auth)
        self.assertEqual(entry["data"]["company"], RESULT.company)
        schedule.async_clear_local_schedules.assert_not_awaited()

    async def test_invalid_header_returns_field_errors_without_network(self):
        config = flow.ConfigFlow()
        with patch.object(flow, "async_discover_device", AsyncMock()) as discover:
            result = await config.async_step_user(
                {**INPUT, "auth": "10000", "company": "GG"}
            )
        self.assertEqual(
            result["errors"], {"auth": "invalid_auth", "company": "invalid_company"}
        )
        discover.assert_not_awaited()

    async def test_no_reply_never_creates_entry(self):
        config = flow.ConfigFlow()
        with patch.object(
            flow,
            "async_discover_device",
            AsyncMock(side_effect=flow.DiscoveryTimeoutError),
        ):
            result = await config.async_step_user(INPUT)
        self.assertEqual(result["type"], "form")
        self.assertEqual(result["errors"], {"base": "cannot_connect"})
        self.assertIsNone(config._pending_discovery)

    async def test_incompatible_reply_does_not_create_entry(self):
        config = flow.ConfigFlow()
        other = flow.DiscoveryResult(
            RESULT.host, RESULT.mac, RESULT.company, 3, RESULT.auth
        )
        with patch.object(flow, "async_discover_device", AsyncMock(return_value=other)):
            result = await config.async_step_user(INPUT)
        self.assertEqual(result["errors"], {"model": "model_mismatch"})

    async def test_reconfigure_uses_same_import_and_verification_path(self):
        config = flow.ConfigFlow()
        entry = SimpleNamespace(data={**INPUT, "auth": 0x0403, "company": 0xF1})
        config._get_reconfigure_entry = lambda: entry
        config._abort_if_unique_id_mismatch = Mock()
        initial = await config.async_step_reconfigure()
        user_input = initial["data_schema"](INPUT)
        with patch.object(
            flow, "async_discover_device", AsyncMock(return_value=RESULT)
        ) as discover:
            await config.async_step_reconfigure(user_input)
        self.assertEqual(discover.await_args.kwargs["auth"], 0x0403)
        result = await config.async_step_schedule_cleanup(
            {"clear_local_schedules": False}
        )
        self.assertEqual(result["type"], "update")
        self.assertEqual(result["data_updates"]["auth"], RESULT.auth)
        config._abort_if_unique_id_mismatch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
