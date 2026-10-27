# SPDX-License-Identifier: GPL-3.0-or-later
"""Route-byte tests: devices also broadcast state on route 0x02.

Synthetic UDP tests; no HA installation, live device, or network required.
Only HA's Platform enum is stubbed (same pattern as test_discovery.py).
"""

from __future__ import annotations

import importlib
import sys
import unittest
from enum import StrEnum
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

PACKAGE = "_f072_route_tests_352"
root = Path(__file__).resolve().parents[1] / "custom_components/352air_legacy_local"
package = ModuleType(PACKAGE)
package.__path__ = [str(root)]
protocols = ModuleType(f"{PACKAGE}.protocols")
protocols.__path__ = [str(root / "protocols")]
ha_const = ModuleType("homeassistant.const")
ha_const.Platform = StrEnum("Platform", "FAN SENSOR LIGHT SELECT SWITCH")
with patch.dict(
    sys.modules,
    {
        PACKAGE: package,
        f"{PACKAGE}.protocols": protocols,
        "homeassistant": ModuleType("homeassistant"),
        "homeassistant.const": ha_const,
    },
):
    base = importlib.import_module(f"{PACKAGE}.protocols.base")
    models = importlib.import_module(f"{PACKAGE}.models")
    f072 = importlib.import_module(f"{PACKAGE}.protocols.f072")

MAC = bytes.fromhex("f0fe6ba57967")
AUTH = 0x860C
PEER = ("192.0.2.50", 11530)


def g30_broadcast_frame(route: int) -> bytes:
    """A G30/G45 unsolicited state frame as captured on real hardware.

    The codec's ``data_area`` is ``inner[7:-2]``; per the captured device
    frames that area starts with the two-byte inner sequence, so the state
    fields below use the documented offsets (d3 mode .. d28 airflow).
    """

    data_area = bytearray(31)
    data_area[0:2] = (42).to_bytes(2, "big")  # inner sequence
    data_area[3] = 0x11  # mode 1 (auto) | filter profile 1
    data_area[5] = 0  # timer hours
    data_area[6] = 2  # air quality
    data_area[7] = 0x11  # child lock off
    data_area[8] = 0x00  # display on
    data_area[9] = 0x00  # power on
    data_area[12:14] = (39).to_bytes(2, "big")  # pm25
    data_area[14] = 24  # temperature
    data_area[15] = 50  # humidity
    data_area[16:18] = (700).to_bytes(2, "big")  # co2
    data_area[18] = 0  # ptc
    data_area[27:29] = (200).to_bytes(2, "big")  # airflow
    inner = bytearray(b"\xf0\x72")
    inner += (2 + 3 + len(data_area) + 2).to_bytes(2, "big")
    inner += bytes((0x04, 0x84, 0x02))  # type, response marker, dc
    inner += bytes(data_area)
    inner += base.crc16_genibus(inner[2:]).to_bytes(2, "big")
    context = models.CommandContext(
        identity=models.HeaderIdentity(mac=MAC, company=0xF1, wire_type=4, auth=AUTH),
        outer_sequence=7,
    )
    return base.build_outer_frame(context, bytes((route,)) + bytes(inner))


def codec() -> f072.F072G30Codec:
    return f072.F072G30Codec(models.DeviceModel.G45)


class RouteTests(unittest.TestCase):
    def test_polled_response_route_01_still_decodes(self):
        packet = codec().decode(g30_broadcast_frame(0x01), PEER)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.kind, models.PacketKind.STATE)
        self.assertEqual(packet.raw_metadata["route"], 0x01)
        self.assertEqual(packet.state.power, models.PowerState.ON)
        self.assertEqual(packet.state.pm25, 39)

    def test_device_broadcast_route_02_decodes(self):
        packet = codec().decode(g30_broadcast_frame(0x02), PEER)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.kind, models.PacketKind.STATE)
        self.assertEqual(packet.raw_metadata["route"], 0x02)
        self.assertEqual(packet.state.power, models.PowerState.ON)
        self.assertEqual(packet.state.pm25, 39)
        self.assertEqual(packet.state.airflow_m3h, 200)
        self.assertEqual(packet.state.temperature, 24)
        self.assertEqual(packet.state.humidity, 50)
        self.assertEqual(packet.state.co2, 700)

    def test_unknown_route_rejected(self):
        self.assertIsNone(codec().decode(g30_broadcast_frame(0x03), PEER))


if __name__ == "__main__":
    unittest.main()
