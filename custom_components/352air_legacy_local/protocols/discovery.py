# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only directed discovery helpers for the outer UDP envelope."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from ..models import CommandContext, DiscoveryResult, HeaderIdentity
from .base import (
    DISCOVERY_OUTER_OPERATION,
    build_outer_frame,
    ignore_rejection,
    parse_outer_frame,
    valid_source,
)

DISCOVERY_COMPANY = 0xF1
DISCOVERY_AUTH = 0xCB76
_DEVICE_PORT = 11530


def encode_discovery_probe(
    mac: bytes,
    wire_type: int,
    sequence: int,
    *,
    company: int = DISCOVERY_COMPANY,
    auth: int = DISCOVERY_AUTH,
    operation: int = DISCOVERY_OUTER_OPERATION,
) -> bytes:
    """Build the documented non-mutating directed discovery probe.

    Unknown devices use the app discovery credential. Known devices may use
    their own company/auth, including when this frame is sent by broadcast.
    The app's identity-free builder uses flags 00; directed probes use 04.
    """

    identity = HeaderIdentity(mac=mac, company=company, wire_type=wire_type, auth=auth)
    context = CommandContext(identity=identity, outer_sequence=sequence)
    return build_outer_frame(context, b"\x23", operation=operation)


def decode_discovery_reply(
    datagram: bytes,
    source: tuple[str, int],
    *,
    on_reject: Callable[[str], None] = ignore_rejection,
) -> DiscoveryResult | None:
    """Decode a reply containing ``23 <IPv4> <MAC>`` without assuming offsets."""

    outer = parse_outer_frame(datagram, on_reject=on_reject)
    if outer is None:
        return None
    peer = valid_source(source)
    if peer is None or peer[1] != _DEVICE_PORT:
        on_reject("source_port_or_shape")
        return None
    if outer.operation != 0x06:
        on_reject("discovery_operation")
        return None
    if len(outer.payload) < 11 or outer.payload[0] != 0x23:
        on_reject("discovery_payload")
        return None
    payload = outer.payload
    embedded_mac = payload[5:11]
    if embedded_mac != outer.identity.mac:
        on_reject("embedded_mac_mismatch")
        return None
    try:
        advertised_host = str(ipaddress.IPv4Address(payload[1:5]))
    except ipaddress.AddressValueError:
        on_reject("advertised_address_invalid")
        return None
    if advertised_host not in {peer[0], "0.0.0.0"}:
        on_reject("advertised_address_mismatch")
        return None
    return DiscoveryResult(
        identity=outer.identity,
        host=peer[0],
        source=peer,
        sequence=outer.sequence,
    )
