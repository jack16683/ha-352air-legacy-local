# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real schemas and flow validation with minimal HA UI stand-ins."""

from __future__ import annotations

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

    async def async_set_unique_id(self, unique_id):
        self.unique_id = unique_id

    def _abort_if_unique_id_configured(self, **_kwargs):
        pass

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

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
