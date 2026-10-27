# SPDX-License-Identifier: GPL-3.0-or-later
"""All-model protocol and entity regression with synthetic LAN identities.

Frames use independent struct/CRC calculations at APK payload coordinates.
HA UI classes are stand-ins; production codecs, entities and runtime are used.
No device, Home Assistant instance or network connection is required.
"""

from __future__ import annotations

import asyncio
import binascii
import importlib
import math
import sys
import unittest
from dataclasses import dataclass
from enum import IntFlag, StrEnum
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

importlib.import_module("cryptography.hazmat.primitives.ciphers")


class _Entity:
    pass


class _Fan(_Entity):
    pass


class _Select(_Entity):
    @property
    def options(self):
        return self._attr_options


class _Sensor(_Entity):
    pass


class _Light(_Entity):
    pass


class _Switch(_Entity):
    pass


class _Features(IntFlag):
    SET_SPEED = 1
    PRESET_MODE = 2
    TURN_ON = 4
    TURN_OFF = 8


class _HAError(Exception):
    def __init__(self, *args, **_kwargs):
        super().__init__(*args)


@dataclass(frozen=True, kw_only=True)
class _Description:
    key: str
    translation_key: str | None = None
    icon: str | None = None
    entity_category: str | None = None
    device_class: str | None = None
    native_unit_of_measurement: str | None = None
    state_class: str | None = None
    options: list[str] | None = None


def _module(name, **attributes):
    module = ModuleType(name)
    module.__dict__.update(attributes)
    return module


PACKAGE = "_models_tests_352"
ROOT = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = _module(PACKAGE, ConfigEntry=object, __path__=[str(ROOT)])
ha_const = _module(
    "homeassistant.const",
    Platform=StrEnum("Platform", "FAN SENSOR LIGHT SELECT SWITCH"),
    EntityCategory=SimpleNamespace(CONFIG="config", DIAGNOSTIC="diagnostic"),
    UnitOfDensity=SimpleNamespace(MICROGRAMS_PER_CUBIC_METER="ug/m3"),
    UnitOfRatio=SimpleNamespace(PERCENTAGE="%", PARTS_PER_MILLION="ppm"),
    UnitOfTemperature=SimpleNamespace(CELSIUS="C"),
    UnitOfTime=SimpleNamespace(MINUTES="min"),
    UnitOfVolume=SimpleNamespace(CUBIC_METERS="m3"),
    UnitOfVolumeFlowRate=SimpleNamespace(CUBIC_METERS_PER_HOUR="m3/h"),
)
stubs = {
    PACKAGE: package,
    "homeassistant": _module("homeassistant"),
    "homeassistant.const": ha_const,
    "homeassistant.core": _module(
        "homeassistant.core", HomeAssistant=object, callback=lambda function: function
    ),
    "homeassistant.exceptions": _module(
        "homeassistant.exceptions",
        HomeAssistantError=_HAError,
        ConfigEntryNotReady=_HAError,
        ServiceValidationError=_HAError,
    ),
    "homeassistant.helpers": _module("homeassistant.helpers"),
    "homeassistant.helpers.entity": _module(
        "homeassistant.helpers.entity", Entity=_Entity
    ),
    "homeassistant.helpers.entity_platform": _module(
        "homeassistant.helpers.entity_platform", AddEntitiesCallback=object
    ),
    "homeassistant.helpers.device_registry": _module(
        "homeassistant.helpers.device_registry",
        DeviceInfo=dict,
        CONNECTION_NETWORK_MAC="mac",
    ),
    "homeassistant.helpers.event": _module(
        "homeassistant.helpers.event",
        async_track_time_interval=lambda *_args: lambda: None,
    ),
    "homeassistant.util": _module("homeassistant.util"),
    "homeassistant.util.percentage": _module(
        "homeassistant.util.percentage",
        ordered_list_item_to_percentage=lambda items, item: (
            (items.index(item) + 1) * 100 // len(items)
        ),
        percentage_to_ordered_list_item=lambda items, percentage: items[
            math.ceil(percentage * len(items) / 100) - 1
        ],
    ),
    "homeassistant.components": _module("homeassistant.components"),
    "homeassistant.components.fan": _module(
        "homeassistant.components.fan", FanEntity=_Fan, FanEntityFeature=_Features
    ),
    "homeassistant.components.select": _module(
        "homeassistant.components.select",
        SelectEntity=_Select,
        SelectEntityDescription=_Description,
    ),
    "homeassistant.components.light": _module(
        "homeassistant.components.light",
        LightEntity=_Light,
        LightEntityDescription=_Description,
        ColorMode=SimpleNamespace(ONOFF="onoff"),
    ),
    "homeassistant.components.switch": _module(
        "homeassistant.components.switch",
        SwitchEntity=_Switch,
        SwitchEntityDescription=_Description,
    ),
    "homeassistant.components.sensor": _module(
        "homeassistant.components.sensor",
        SensorEntity=_Sensor,
        SensorEntityDescription=_Description,
        SensorDeviceClass=SimpleNamespace(
            **{
                name: name
                for name in (
                    "PM25",
                    "ENUM",
                    "DURATION",
                    "VOLUME",
                    "TEMPERATURE",
                    "HUMIDITY",
                    "CO2",
                    "VOLUME_FLOW_RATE",
                )
            }
        ),
        SensorStateClass=SimpleNamespace(
            MEASUREMENT="measurement", TOTAL_INCREASING="total_increasing"
        ),
    ),
}
with patch.dict(sys.modules, stubs):
    models = importlib.import_module(f"{PACKAGE}.models")
    protocols = importlib.import_module(f"{PACKAGE}.protocols")
    const = importlib.import_module(f"{PACKAGE}.const")
    discovery = importlib.import_module(f"{PACKAGE}.discovery")
    runtime_module = importlib.import_module(f"{PACKAGE}.runtime")
    fan = importlib.import_module(f"{PACKAGE}.fan")
    select = importlib.import_module(f"{PACKAGE}.select")
    sensor = importlib.import_module(f"{PACKAGE}.sensor")
    light = importlib.import_module(f"{PACKAGE}.light")
    switch = importlib.import_module(f"{PACKAGE}.switch")
    schedule = importlib.import_module(f"{PACKAGE}.schedule")

HOST = "192.0.2.123"
MAC = bytes.fromhex("123456789abc")
PEER = (HOST, 11530)
WIRE_TYPES = {
    "M25": 1,
    "X83": 2,
    "X83C": 2,
    "X83C_PLUS": 2,
    "X50": 3,
    "X50S": 3,
    "X60": 3,
    "X70": 3,
    "G30": 4,
    "G45": 4,
}


def identity(name):
    return models.HeaderIdentity(MAC, 0xF1, WIRE_TYPES[name], 0xD3E7)


def context(name):
    return models.CommandContext(
        identity(name), 0x1234, 0x5678, models.DeviceModel[name]
    )


def envelope(name, payload, *, operation=4):
    return (
        b"\xa1"
        + bytes((operation,))
        + MAC
        + bytes((len(payload) + 7, 0))
        + b"\x12\x34\xf1"
        + bytes((WIRE_TYPES[name],))
        + b"\xd3\xe7"
        + payload
    )


def crc(data):
    return (binascii.crc_hqx(data, 0xFFFF) ^ 0xFFFF).to_bytes(2, "big")


def f072_request(name, command, value, *, airflow=False):
    encoded = value.to_bytes(2, "big") if airflow else bytes((value, 0))
    inner = b"\xf0\x72\x00\x0d" + bytes((WIRE_TYPES[name], 4, 2))
    inner += b"\x56\x78\x03" + bytes((command,)) + encoded
    return b"\x01" + inner + crc(inner[2:])


def status(name, *, marker=0x84):
    wire = WIRE_TYPES[name]
    if wire == 1:
        payload = bytearray(b"\x04\xf5\xa1" + bytes(14))
        payload[3:5] = b"\x01\x23"
        payload[7] = 1
        return envelope(name, payload)
    area = bytearray(29 if wire == 4 else 30)
    area[3:10] = bytes((0x11, 3, 1, 2, 0x11 if wire == 2 else 0, 0, 0))
    area[10:14] = b"\x00\x3c\x01\x23"
    if wire == 4:
        area[14:19] = b"\x17\x2d\x01\xf4\x01"
        area[27:29] = (450 if name == "G45" else 300).to_bytes(2, "big")
    elif wire == 3:
        area[29] = 1
    if wire == 2:
        # A5 fields are indexed in the routed payload itself, whereas F072
        # indexes its separate status data area after the response header.
        return envelope(name, b"\x02\x5a\xa1" + area[3:] + bytes(3))
    payload = b"\x01\xf0\x72\x00" + bytes((len(area) + 7, wire, marker, 2)) + area
    return envelope(name, payload + crc(payload[3:]))


def codec(name):
    return protocols.codec_for_model(models.DeviceModel[name])


class ProtocolTests(unittest.TestCase):
    def test_f072_routes_across_all_models_and_validation_boundaries(self):
        for name in ("X50", "X50S", "X60", "X70", "G30", "G45"):
            with self.subTest(model=name):
                response = status(name)
                broadcast = bytearray(response)
                broadcast[16] = 0x02
                expected = codec(name).decode(response, PEER)
                decoded = codec(name).decode(bytes(broadcast), PEER)
                self.assertIsNotNone(expected)
                self.assertIsNotNone(decoded)
                self.assertEqual(decoded.state, expected.state)
                self.assertEqual(decoded.raw_metadata["route"], 0x02)
                self.assertIsNotNone(
                    discovery._decode_passive_status(
                        bytes(broadcast), PEER, HOST, MAC, {WIRE_TYPES[name]}
                    )
                )
                corrupt = bytearray(broadcast)
                corrupt[-1] ^= 1
                self.assertIsNone(codec(name).decode(bytes(corrupt), PEER))
                self.assertIsNone(
                    discovery._decode_passive_status(
                        bytes(corrupt), PEER, HOST, MAC, {WIRE_TYPES[name]}
                    )
                )
                broadcast[16] = 0x03
                self.assertIsNone(codec(name).decode(bytes(broadcast), PEER))

        self.assertIsNone(codec("G45").decode(status("X50"), PEER))
        self.assertIsNone(codec("X50").decode(status("G45"), PEER))

    def test_g45_broadcast_is_discoverable_and_still_requires_valid_crc(self):
        raw = bytearray(status("G45"))
        raw[16] = 0x02
        receiver = discovery._ReadOnlyNetworkDiscoveryProtocol({42})
        receiver.datagram_received(bytes(raw), PEER)
        self.assertEqual(receiver.results[MAC.hex(":")].wire_type, 4)
        self.assertIsNotNone(
            discovery._decode_passive_status(bytes(raw), PEER, HOST, MAC, {4})
        )
        raw[-1] ^= 1
        self.assertIsNone(
            discovery._decode_passive_status(bytes(raw), PEER, HOST, MAC, {4})
        )
        raw[-1] ^= 1
        raw[16] = 0x03
        self.assertIsNone(
            discovery._decode_passive_status(bytes(raw), PEER, HOST, MAC, {4})
        )

    def test_all_ten_models_have_matching_family_and_wire_metadata(self):
        self.assertEqual(set(WIRE_TYPES), set(const.MODEL_OPTIONS))
        self.assertEqual(set(WIRE_TYPES), set(models.DeviceModel.__members__))
        for name, wire in WIRE_TYPES.items():
            with self.subTest(model=name):
                self.assertEqual(const.MODEL_WIRE_TYPES[name], (wire,))
                self.assertIn(name, const.compatible_models(wire))
                self.assertEqual(
                    codec(name).family,
                    models.family_for_model(models.DeviceModel[name]),
                )

    def test_queries_match_independent_apk_layout_for_every_model(self):
        for name, wire in WIRE_TYPES.items():
            with self.subTest(model=name):
                if wire == 1:
                    payload = b"\x03\xfa\xa0\x11\x11\x00\x00"
                elif wire == 2:
                    payload = b"\x01\xa5\xa0\x11\x11\x00\x00"
                else:
                    payload = f072_request(name, 0x11, 0x11)
                self.assertEqual(
                    codec(name).encode_query(context(name)), envelope(name, payload)
                )

    def test_all_model_status_fields_and_passive_identity_learning(self):
        for name, wire in WIRE_TYPES.items():
            markers = (0x84, 0x03) if wire in {3, 4} else (0x84,)
            for marker in markers:
                with self.subTest(model=name, marker=marker):
                    raw = status(name, marker=marker)
                    decoded = codec(name).decode(raw, PEER)
                    self.assertIsNotNone(decoded)
                    self.assertEqual(decoded.state.pm25, 291)
                    self.assertEqual(decoded.kind, models.PacketKind.STATE)
                    learned = discovery._decode_passive_status(
                        raw, PEER, HOST, MAC, {wire}
                    )
                    self.assertIsNotNone(learned)
                    self.assertEqual(learned.auth, 0xD3E7)
                    if wire != 1:
                        self.assertEqual(decoded.state.power, models.PowerState.ON)
                        self.assertEqual(decoded.state.timer_remaining_minutes, 60)
                        self.assertTrue(decoded.state.child_lock)
                        self.assertTrue(decoded.state.display_on)
                    if wire == 4:
                        self.assertEqual(
                            decoded.state.airflow, 450 if name == "G45" else 300
                        )
                        self.assertEqual(decoded.state.temperature, 23)
                        self.assertEqual(decoded.state.humidity, 45)
                        self.assertEqual(decoded.state.co2, 500)

    def test_every_model_rejects_truncated_trailing_and_wrong_source_state(self):
        for name, wire in WIRE_TYPES.items():
            with self.subTest(model=name):
                raw = status(name)
                for size in range(len(raw)):
                    self.assertIsNone(codec(name).decode(raw[:size], PEER))
                self.assertIsNone(codec(name).decode(raw + b"\x00", PEER))
                self.assertIsNone(
                    discovery._decode_passive_status(
                        raw, (HOST, 9999), HOST, MAC, {wire}
                    )
                )
                if wire in {3, 4}:
                    damaged = raw[:-1] + bytes((raw[-1] ^ 1,))
                    self.assertIsNone(codec(name).decode(damaged, PEER))
                    self.assertIsNone(
                        discovery._decode_passive_status(
                            damaged, PEER, HOST, MAC, {wire}
                        )
                    )

    def test_controls_match_apk_codes_and_family_boolean_values(self):
        for name, wire in WIRE_TYPES.items():
            if wire == 1:
                continue
            for operation, command_code in (
                ("power", 0x5E),
                ("display", 0x56),
                ("child_lock", 0x55),
            ):
                for enabled in (False, True):
                    with self.subTest(model=name, operation=operation, enabled=enabled):
                        if operation == "power" and wire == 2:
                            value = 0x35 if enabled else 0x11
                        elif operation == "child_lock" and wire == 2:
                            value = 0x11 if enabled else 0
                        else:
                            value = 0 if enabled else 0x11
                        actual_value = runtime_module._wire_command_value(
                            name, operation, enabled
                        )
                        self.assertEqual(actual_value, value)
                        command = models.Command(
                            models.CommandOperation(operation), actual_value
                        )
                        if wire == 2:
                            inner = bytes((0xA5, 0xA0, command_code, value, 0))
                            payload = b"\x01" + inner + bytes((sum(inner) & 0xFF,))
                        else:
                            payload = f072_request(name, command_code, value)
                        self.assertEqual(
                            codec(name).encode_command(context(name), command),
                            envelope(name, payload),
                        )

    def test_mode_timer_speed_and_heating_commands_for_each_purifier(self):
        for name, wire in WIRE_TYPES.items():
            if wire == 1:
                continue
            controls = [("timer", 0x54, value) for value in (0, 1, 2, 3, 5, 8)]
            modes = (1, 5) if wire == 4 else (1, 2, 3, 5)
            controls += [("mode", 0x51, value) for value in modes]
            if wire in {2, 3}:
                controls += [
                    ("speed", 0x52, value) for value in range(1, 7 if wire == 2 else 6)
                ]
            if wire == 4:
                controls += [("ptc", 0x53, value) for value in (0, 1, 2)]
            for operation, code, value in controls:
                with self.subTest(model=name, operation=operation, value=value):
                    command = models.Command(models.CommandOperation(operation), value)
                    if wire == 2:
                        inner = bytes((0xA5, 0xA0, code, value, 0))
                        payload = b"\x01" + inner + bytes((sum(inner) & 0xFF,))
                    else:
                        payload = f072_request(name, code, value)
                    self.assertEqual(
                        codec(name).encode_command(context(name), command),
                        envelope(name, payload),
                    )
            with self.assertRaises(models.InvalidCommandError):
                codec(name).encode_command(
                    context(name), models.Command(models.CommandOperation.MODE, 4)
                )
            if wire == 3:
                with self.assertRaises(models.InvalidCommandError):
                    codec(name).encode_command(
                        context(name), models.Command(models.CommandOperation.SPEED, 6)
                    )

    def test_m25_cannot_send_purifier_controls(self):
        detector = codec("M25")
        for operation in models.CommandOperation:
            if operation is not models.CommandOperation.BACKLIGHT:
                with (
                    self.subTest(operation=operation),
                    self.assertRaises(models.InvalidCommandError),
                ):
                    detector.encode_command(
                        context("M25"), models.Command(operation, 1)
                    )
        for value in (0, 1):
            inner = bytes((0xFA, 0xA3, 3, 1, value, 0xA1 + value))
            actual = detector.encode_command(
                context("M25"), models.Command(models.CommandOperation.BACKLIGHT, value)
            )
            self.assertEqual(actual, envelope("M25", b"\x03" + inner))

    def test_g30_g45_flow_bounds_and_percent_endpoints(self):
        for name, maximum in (("G30", 300), ("G45", 450)):
            for flow in (40, maximum):
                with self.subTest(model=name, flow=flow):
                    command = models.Command(models.CommandOperation.AIRFLOW, flow)
                    self.assertEqual(
                        codec(name).encode_command(context(name), command),
                        envelope(name, f072_request(name, 0x58, flow, airflow=True)),
                    )
            for flow in (39, 41, maximum + 5):
                with (
                    self.subTest(model=name, flow=flow),
                    self.assertRaises(models.InvalidCommandError),
                ):
                    codec(name).encode_command(
                        context(name),
                        models.Command(models.CommandOperation.AIRFLOW, flow),
                    )
            for percent, expected in ((1, 40), (100, maximum)):
                self.assertEqual(
                    codec(name).flow_for_percentage(percent, context(name)), expected
                )
            for percentage in range(1, 101):
                flow = codec(name).flow_for_percentage(percentage, context(name))
                self.assertTrue(40 <= flow <= maximum and flow % 5 == 0)

    def test_all_purifier_schedule_frames_keep_learned_identity_and_crc(self):
        empty = (b"\x00\xff\xff\xff\xff\x00\x00\x00",) * 4
        for name, wire in WIRE_TYPES.items():
            self.assertEqual(schedule.schedule_cleanup_supported(wire), wire != 1)
            if wire == 1:
                continue
            device = discovery.DiscoveryResult(HOST, MAC.hex(":"), 0xF1, wire, 0xD3E7)
            for raw in (
                schedule._encode_schedule_query(device, 0x1234),
                schedule._encode_schedule_write(device, 0x1234, empty),
            ):
                with self.subTest(model=name, length=len(raw)):
                    self.assertEqual(raw[2:8], MAC)
                    self.assertEqual(raw[12:16], bytes((0xF1, wire, 0xD3, 0xE7)))
                    self.assertEqual(raw[16:19], b"\x01\xf0\x72")
                    self.assertEqual(raw[-2:], crc(raw[19:-2]))


class BroadcastRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_g45_broadcast_updates_client_state_and_listener(self):
        client = runtime_module.LocalDeviceClient(
            host=HOST, identity=identity("G45"), model=models.DeviceModel.G45
        )
        client._loop = asyncio.get_running_loop()
        seen = []
        client.add_listener(seen.append)
        raw = bytearray(status("G45"))
        raw[16] = 0x02
        client._datagram_received(bytes(raw), PEER)
        self.assertTrue(client.available)
        self.assertEqual(client.state.pm25, 291)
        self.assertEqual(seen, [client.state])


class EntityTests(unittest.IsolatedAsyncioTestCase):
    def make_runtime(self, name):
        state = codec(name).decode(status(name), PEER).state
        client = SimpleNamespace(command=AsyncMock(return_value=state))
        return runtime_module.RuntimeData(
            Mock(), Mock(), client, name, MAC.hex(":"), state, True, 0
        )

    async def test_life_power_entity_exists_only_when_enabled_and_readable(self):
        identity = SimpleNamespace(unique_id="life:fixture:device")
        local_runtime = switch.LocalDiscoveryRuntime(Mock(), Mock(), identity)
        entry = SimpleNamespace(runtime_data=local_runtime)
        entities = []
        await switch.async_setup_entry(None, entry, entities.extend)
        self.assertEqual(entities, [])
        local_runtime.power_client = Mock()
        local_runtime.reachable = True
        await switch.async_setup_entry(None, entry, entities.extend)
        self.assertEqual(len(entities), 1)
        self.assertFalse(entities[0].available)
        local_runtime.power_state = False
        self.assertTrue(entities[0].available)
        self.assertFalse(entities[0].is_on)

    async def test_life_credentials_are_redacted_from_diagnostics(self):
        def redact(data, keys):
            if isinstance(data, dict):
                return {
                    key: "**REDACTED**" if key in keys else redact(value, keys)
                    for key, value in data.items()
                }
            return data

        diagnostics_stub = _module(
            "homeassistant.components.diagnostics", async_redact_data=redact
        )
        package.LocalConfigEntry = object
        with patch.dict(
            sys.modules,
            {**stubs, "homeassistant.components.diagnostics": diagnostics_stub},
        ):
            diagnostic = importlib.import_module(f"{PACKAGE}.diagnostics")
        entry = SimpleNamespace(
            data={
                "life_access_key": "fixture-key",
                "life_access_token": "fixture-token",
            },
            runtime_data=SimpleNamespace(diagnostics_snapshot=dict),
        )
        result = await diagnostic.async_get_config_entry_diagnostics(None, entry)
        self.assertEqual(result["entry"]["life_access_key"], "**REDACTED**")
        self.assertEqual(result["entry"]["life_access_token"], "**REDACTED**")

    async def test_entity_scopes_for_all_ten_models(self):
        for name, wire in WIRE_TYPES.items():
            with self.subTest(model=name):
                runtime = self.make_runtime(name)
                entry = SimpleNamespace(runtime_data=runtime)
                collected = {}
                for component in (fan, select, sensor, light, switch):
                    entities = []
                    await component.async_setup_entry(
                        None,
                        entry,
                        lambda values, target=entities: target.extend(values),
                    )
                    collected[component.__name__.rsplit(".", 1)[-1]] = entities
                self.assertEqual(len(collected["fan"]), int(name != "M25"))
                self.assertEqual(len(collected["light"]), int(name != "M25"))
                self.assertEqual(len(collected["switch"]), int(name != "M25"))
                select_keys = {
                    entity.entity_description.key for entity in collected["select"]
                }
                self.assertEqual(
                    select_keys,
                    {"backlight_mode"}
                    if name == "M25"
                    else {"timer", "ptc"}
                    if name in {"G30", "G45"}
                    else {"timer"},
                )
                sensors = {
                    entity.entity_description.key: entity
                    for entity in collected["sensor"]
                }
                self.assertEqual(sensors["pm25"].native_value, 291)
                for key in ("temperature", "humidity", "co2"):
                    self.assertEqual(key in sensors, name in {"G30", "G45"})
                if name == "M25":
                    self.assertEqual(set(sensors), {"pm25", "linkage_state"})
                else:
                    self.assertEqual(sensors["timer_remaining"].native_value, 60)
                    self.assertEqual(
                        collected["fan"][0].speed_count,
                        100 if name in {"G30", "G45"} else 6 if wire == 2 else 5,
                    )

    async def test_model_presets_and_manual_mode_do_not_emit_mode_four(self):
        for name, wire in WIRE_TYPES.items():
            if wire == 1:
                continue
            with self.subTest(model=name):
                runtime = self.make_runtime(name)
                entity = fan.LegacyPurifierFan(runtime)
                expected = (
                    {"auto", "manual", "deep_clean"}
                    if wire == 4
                    else {"auto", "manual", "sleep", "turbo"}
                )
                if name not in {"X83C", "X50S"} and wire != 4:
                    expected.add("deep_clean")
                self.assertEqual(set(entity.preset_modes), expected)
                await entity.async_set_preset_mode("manual")
                command = runtime.client.command.await_args.args[0]
                self.assertEqual(
                    command.operation,
                    models.CommandOperation.PERCENTAGE
                    if wire == 4
                    else models.CommandOperation.SPEED,
                )
                codec(name).encode_command(context(name), command)
                runtime.client.command.reset_mock()
                await entity.async_set_percentage(0)
                self.assertEqual(
                    runtime.client.command.await_args.args[0],
                    models.Command(models.CommandOperation.POWER, 0x11),
                )


if __name__ == "__main__":
    unittest.main()
