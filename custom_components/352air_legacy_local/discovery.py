# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only UDP discovery for legacy 352 devices.

This module intentionally knows only the documented outer discovery envelope. It
does not import the device protocol implementation and never sends a control,
provisioning, or lock packet.
"""

from __future__ import annotations

import asyncio
import ipaddress
from contextlib import suppress
from dataclasses import dataclass

from .const import DISCOVERY_TIMEOUT_SECONDS, UDP_PORT, mac_to_bytes, normalize_mac
from .protocols.discovery import decode_discovery_reply, encode_discovery_probe
from .udp import async_acquire_udp_endpoint, async_release_udp_endpoint


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Header identity learned from a read-only discovery reply."""

    host: str
    mac: str
    company: int
    wire_type: int
    auth: int

    def as_entry_data(self) -> dict[str, str | int]:
        """Return the persistable discovery data, excluding any model choice."""
        return {
            "host": self.host,
            "mac": self.mac,
            "company": self.company,
            "wire_type": self.wire_type,
            "auth": self.auth,
        }


class DiscoveryError(Exception):
    """Base class for a safe discovery failure."""


class DiscoveryTimeoutError(DiscoveryError):
    """No matching response arrived before the probing deadline."""


def _decode_reply(
    datagram: bytes,
    source: tuple[str, int],
    expected_mac: bytes,
    sequences: set[int],
) -> DiscoveryResult | None:
    """Validate the small discovery subset needed to learn a header identity."""
    decoded = decode_discovery_reply(datagram, source)
    if (
        decoded is None
        or decoded.identity.mac != expected_mac
        or (sequences and decoded.sequence not in sequences)
    ):
        return None

    return DiscoveryResult(
        host=decoded.host,
        mac=normalize_mac(decoded.identity.mac),
        company=decoded.identity.company,
        wire_type=decoded.identity.wire_type,
        auth=decoded.identity.auth,
    )


class _ReadOnlyDiscoveryProtocol:
    """Collect the first matching reply without retaining packet contents."""

    def __init__(self, expected_mac: bytes, sequences: set[int]) -> None:
        self._expected_mac = expected_mac
        self._sequences = sequences
        self.result: DiscoveryResult | None = None
        self.response_received = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.result is not None:
            return
        result = _decode_reply(data, addr, self._expected_mac, self._sequences)
        if result is not None:
            self.result = result
            self.response_received.set()


async def async_discover_device(
    host: str,
    mac: str | bytes,
    wire_types: tuple[int, ...] = (1, 2, 3, 4),
    *,
    response_timeout: float = DISCOVERY_TIMEOUT_SECONDS,
) -> DiscoveryResult:
    """Probe a known address/MAC with only documented read-only packets.

    Runtime and discovery share one local UDP 11530 endpoint because these
    devices reply to that fixed port rather than the request's source port.
    """
    parsed_host = ipaddress.ip_address(host)
    if parsed_host.version != 4:
        raise DiscoveryError("Only IPv4 addresses are supported")

    target_mac = mac_to_bytes(mac)
    selected_wire_types = tuple(dict.fromkeys(wire_types))
    if not selected_wire_types or any(
        wire_type not in range(1, 5) for wire_type in selected_wire_types
    ):
        raise DiscoveryError("Unsupported discovery wire type")

    sequences = {
        ((index + 1) * 0x1F31) & 0xFFFF
        for index, _wire_type in enumerate(selected_wire_types)
    }
    protocol = _ReadOnlyDiscoveryProtocol(target_mac, sequences)
    endpoint = None
    resend_task: asyncio.Task[None] | None = None
    try:
        try:
            endpoint = await async_acquire_udp_endpoint(protocol.datagram_received)
        except OSError as err:
            raise DiscoveryError("Unable to bind local UDP port 11530") from err

        def send_probes() -> None:
            assert endpoint is not None
            for index, wire_type in enumerate(selected_wire_types):
                sequence = ((index + 1) * 0x1F31) & 0xFFFF
                endpoint.sendto(
                    encode_discovery_probe(target_mac, wire_type, sequence),
                    (str(parsed_host), UDP_PORT),
                )

        async def resend_once() -> None:
            await asyncio.sleep(min(0.75, response_timeout / 3))
            if not protocol.response_received.is_set():
                send_probes()

        send_probes()
        resend_task = asyncio.create_task(
            resend_once(), name="352air read-only discovery retry"
        )
        try:
            await asyncio.wait_for(
                protocol.response_received.wait(), timeout=response_timeout
            )
        except TimeoutError as err:
            raise DiscoveryTimeoutError from err

        if protocol.result is None:
            raise DiscoveryTimeoutError
        return protocol.result
    finally:
        if resend_task is not None and not resend_task.done():
            resend_task.cancel()
            with suppress(asyncio.CancelledError):
                await resend_task
        if endpoint is not None:
            await async_release_udp_endpoint(endpoint, protocol.datagram_received)
