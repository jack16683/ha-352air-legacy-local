# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only 352Life device-info and ALCS discovery envelopes.

Only NON GET discovery requests and empty ACKs are encoded. No provisioning,
binding, authorization, property write, or generic request API is exposed.
CoAP framing follows RFC 7252; JSON layouts follow the 352Life discovery SDK.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from ..const import normalize_mac
from ..life_models import LIFE_PRODUCTS

COAP_PORT = 5683
ALCS_MULTICAST = "224.0.1.187"
MAX_DATAGRAM = 32768
MAX_DEVICES = 64

DISCOVERY_METHODS: dict[str, tuple[str, str]] = {
    "device_info": ("/sys/device/info/get", "device.info.get"),
    "alcs": ("/dev/core/service/dev", "core.service.dev"),
}


@dataclass(frozen=True, slots=True)
class LocalIdentity:
    """A responding product identity, with no assertion of authorization."""

    host: str
    product_key: str
    device_name: str
    mechanism: str
    mac: str | None = None
    firmware: str | None = None

    @property
    def unique_id(self) -> str:
        """Use protocol identity rather than a DHCP address or display name."""
        return f"life:{self.product_key}:{self.device_name}"

    @property
    def model(self) -> str:
        return LIFE_PRODUCTS[self.product_key].model

    @property
    def name(self) -> str:
        return LIFE_PRODUCTS[self.product_key].name

    def as_entry_data(self) -> dict[str, str]:
        data = {
            "connection_type": "local_discovery",
            "host": self.host,
            "product_key": self.product_key,
            "device_name": self.device_name,
            "model": self.model,
            "discovery_mechanism": self.mechanism,
        }
        if self.mac is not None:
            data["mac"] = self.mac
        if self.firmware is not None:
            data["firmware"] = self.firmware
        return data


@dataclass(frozen=True, slots=True)
class CoapResponse:
    """A complete, successful discovery representation."""

    token: bytes
    message_id: int
    confirmable: bool
    payload: bytes


def encode_discovery_request(
    mechanism: str, token: bytes, message_id: int, request_id: str
) -> bytes:
    """Build the two known read-only requests, without arbitrary URI support."""
    path, method = DISCOVERY_METHODS[mechanism]
    if len(token) != 8 or not 0 <= message_id <= 65535:
        raise ValueError("Invalid CoAP request correlation")
    payload = json.dumps(
        {"id": request_id, "version": "1.0", "method": method, "params": {}},
        separators=(",", ":"),
    ).encode()
    packet = bytearray(b"\x58\x01" + message_id.to_bytes(2, "big") + token)
    previous = 0
    for part in path.strip("/").split("/"):
        value = part.encode("ascii")
        # Every supported URI segment and delta fits in a single nibble.
        packet.append(((11 - previous) << 4) | len(value))
        packet.extend(value)
        previous = 11
    packet.extend(b"\x11\x32")  # Content-Format (12): application/json (50).
    packet.append(0xFF)
    packet.extend(payload)
    return bytes(packet)


def _option_value(nibble: int, data: bytes, offset: int) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    size = {13: 1, 14: 2}.get(nibble)
    if size is None or offset + size > len(data):
        raise ValueError("Malformed CoAP option")
    value = int.from_bytes(data[offset : offset + size], "big")
    return value + (13 if size == 1 else 269), offset + size


def decode_response(data: bytes) -> CoapResponse | None:
    """Reject truncated, fragmented, unsupported, and non-response messages."""
    if not 4 <= len(data) <= MAX_DATAGRAM or data[0] >> 6 != 1:
        return None
    token_length = data[0] & 15
    message_type = (data[0] >> 4) & 3
    # NON requests cannot have piggybacked ACK responses. Separate CON replies
    # are valid, and receive an empty ACK after correlation is checked.
    if token_length != 8 or message_type not in {0, 1} or data[1] >> 5 != 2:
        return None
    offset = 4 + token_length
    if offset >= len(data):
        return None
    option_number = 0
    seen_singletons: set[int] = set()
    try:
        while offset < len(data) and data[offset] != 0xFF:
            header = data[offset]
            offset += 1
            delta, offset = _option_value(header >> 4, data, offset)
            length, offset = _option_value(header & 15, data, offset)
            option_number += delta
            if offset + length > len(data):
                return None
            value = data[offset : offset + length]
            offset += length
            if option_number in {12, 23}:
                if option_number in seen_singletons:
                    return None
                seen_singletons.add(option_number)
            if option_number == 12:
                if len(value) > 2 or int.from_bytes(value, "big") not in {0, 50}:
                    return None
            elif option_number == 23:
                # No block assembly is attempted. Block zero with M=0 is whole.
                if len(value) > 3 or int.from_bytes(value, "big") >> 3:
                    return None
            elif option_number & 1 and option_number not in {1, 3, 5, 7, 11, 15, 17}:
                return None
    except ValueError:
        return None
    if offset >= len(data) - 1:
        return None
    return CoapResponse(
        data[4 : 4 + token_length],
        int.from_bytes(data[2:4], "big"),
        message_type == 0,
        data[offset + 1 :],
    )


def encode_ack(response: CoapResponse) -> bytes:
    """Acknowledge a correlated CON reply without invoking a device operation."""
    return b"\x60\x00" + response.message_id.to_bytes(2, "big")


def _text(value: object, max_length: int) -> str | None:
    if (
        isinstance(value, str)
        and 0 < len(value) <= max_length
        and value.isprintable()
        and value == value.strip()
    ):
        return value
    return None


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _identity(
    profile: dict[str, Any],
    source_host: str,
    mechanism: str,
    *,
    alcs: bool = False,
    parent_address: object = None,
    parent_port: object = None,
) -> LocalIdentity | None:
    product_key = _text(profile.get("prodKey" if alcs else "productKey"), 32)
    device_name = _text(profile.get("name" if alcs else "deviceName"), 128)
    if product_key not in LIFE_PRODUCTS or device_name is None:
        return None
    advertised = profile.get("addr" if alcs else "ip")
    if advertised is None or advertised == "":
        advertised = parent_address
    if advertised is not None and not isinstance(advertised, str):
        return None
    if advertised not in {None, "", "0.0.0.0", source_host}:
        return None
    port = profile.get("port", parent_port)
    if port is not None and (type(port) is not int or port not in {0, COAP_PORT}):
        return None
    mac = None
    raw_mac = profile.get("mac")
    if raw_mac is not None and raw_mac != "":
        try:
            mac = normalize_mac(raw_mac)
        except (AttributeError, TypeError, ValueError):
            return None
        if mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
            return None
    assert product_key is not None
    return LocalIdentity(
        source_host,
        product_key,
        device_name,
        mechanism,
        mac,
        _text(profile.get("fwVersion"), 64),
    )


def decode_identities(
    payload: bytes, source_host: str, mechanism: str, request_id: str
) -> tuple[LocalIdentity, ...]:
    """Validate response correlation, known products, and source-owned identity.

    Never persist AWSS tokens, random values, arbitrary device models, service
    URLs, or other response fields. Discovery is not authenticated control.
    """
    try:
        address = ipaddress.IPv4Address(source_host)
        if address.is_unspecified or address.is_multicast:
            return ()
        body = json.loads(payload, object_pairs_hook=_json_object)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return ()
    if not isinstance(body, dict):
        return ()
    response_id = body.get("id")
    if type(response_id) not in {str, int} or str(response_id) != request_id:
        return ()
    if type(body.get("code")) is not int or body["code"] != 200:
        return ()
    data = body.get("data")
    if not isinstance(data, dict):
        return ()
    profiles: list[tuple[dict[str, Any], object, object]] = []
    if mechanism == "device_info":
        profiles.append((data, None, None))
    elif mechanism == "alcs":
        device_model = data.get("deviceModel")
        if isinstance(device_model, dict):
            profile = device_model.get("profile")
            if isinstance(profile, dict):
                profiles.append((profile, None, None))
        devices = data.get("devices")
        if isinstance(devices, dict) and isinstance(devices.get("profile"), list):
            profiles.extend(
                (profile, devices.get("addr"), devices.get("port"))
                for profile in devices["profile"][:MAX_DEVICES]
                if isinstance(profile, dict)
            )
    identities: dict[str, LocalIdentity] = {}
    for profile, parent_address, parent_port in profiles[:MAX_DEVICES]:
        try:
            identity = _identity(
                profile,
                source_host,
                mechanism,
                alcs=mechanism == "alcs",
                parent_address=parent_address,
                parent_port=parent_port,
            )
        except (TypeError, ValueError):
            continue
        if identity is not None:
            identities[identity.unique_id] = identity
    return tuple(identities.values())
