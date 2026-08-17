# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only directed discovery helpers for the outer UDP envelope."""

from __future__ import annotations

import ipaddress

from ..models import CommandContext, DiscoveryResult, HeaderIdentity
from .base import (
    DISCOVERY_OUTER_OPERATION,
    build_outer_frame,
    parse_outer_frame,
    valid_source,
)

DISCOVERY_COMPANY = 0xF1
DISCOVERY_AUTH = 0xCB76
_DEVICE_PORT = 11530


def encode_discovery_probe(mac: bytes, wire_type: int, sequence: int) -> bytes:
    """Build the documented non-mutating directed discovery probe.

    Discovery deliberately uses its documented fixed company/auth header.  A
    normal device client must instead use header values learned from replies.
    """

    identity = HeaderIdentity(
        mac=mac, company=DISCOVERY_COMPANY, wire_type=wire_type, auth=DISCOVERY_AUTH
    )
    context = CommandContext(identity=identity, outer_sequence=sequence)
    return build_outer_frame(context, b"\x23", operation=DISCOVERY_OUTER_OPERATION)


def decode_discovery_reply(
    datagram: bytes, source: tuple[str, int]
) -> DiscoveryResult | None:
    """Decode a reply containing ``23 <IPv4> <MAC>`` without assuming offsets."""

    outer = parse_outer_frame(datagram)
    peer = valid_source(source)
    if (
        outer is None
        or peer is None
        or peer[1] != _DEVICE_PORT
        or outer.operation != 0x06
        or len(outer.payload) < 11
        or outer.payload[0] != 0x23
    ):
        return None
    payload = outer.payload
    embedded_mac = payload[5:11]
    if embedded_mac != outer.identity.mac:
        return None
    try:
        advertised_host = str(ipaddress.IPv4Address(payload[1:5]))
    except ipaddress.AddressValueError:
        return None
    if advertised_host not in {peer[0], "0.0.0.0"}:
        return None
    return DiscoveryResult(
        identity=outer.identity,
        host=peer[0],
        source=peer,
        sequence=outer.sequence,
    )
