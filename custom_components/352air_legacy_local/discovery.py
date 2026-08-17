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

from .const import (
    DISCOVERY_PASSIVE_TIMEOUT_SECONDS,
    DISCOVERY_TIMEOUT_SECONDS,
    UDP_PORT,
    mac_to_bytes,
    normalize_mac,
)
from .protocols.base import f072_response_crc_is_valid, parse_outer_frame
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


def _decode_passive_status(
    datagram: bytes,
    source: tuple[str, int],
    expected_host: str,
    expected_mac: bytes,
    wire_types: set[int],
) -> DiscoveryResult | None:
    """Learn identity from a strictly validated, non-mutating state broadcast."""
    if source != (expected_host, UDP_PORT):
        return None
    outer = parse_outer_frame(datagram)
    if (
        outer is None
        or outer.operation != 0x04
        or outer.identity.mac != expected_mac
        or outer.identity.wire_type not in wire_types
    ):
        return None

    payload = outer.payload
    wire_type = outer.identity.wire_type
    valid_state = False
    if wire_type == 1:
        valid_state = (
            len(payload) == 17
            and payload[:2] == b"\x03\xe5"
            and payload[2] in {0xA1, 0xA2}
        )
    elif wire_type == 2:
        valid_state = (
            len(payload) in {33, 65}
            and payload[:3] == b"\x02\x5a\xa1"
            and (len(payload) == 33 or payload[33:35] == b"\x5a\xa1")
        )
    elif wire_type in {3, 4} and len(payload) >= 16 and payload[0] == 0x01:
        frame = payload[1:]
        minimum_data_length = 30 if wire_type == 3 else 29
        valid_state = (
            len(frame) >= minimum_data_length + 10
            and frame[:2] == b"\xf0\x72"
            and frame[6] in {0x84, 0x03}
            and frame[7] == 0x02
            and f072_response_crc_is_valid(frame)
        )
    if not valid_state:
        return None

    return DiscoveryResult(
        host=expected_host,
        mac=normalize_mac(outer.identity.mac),
        company=outer.identity.company,
        wire_type=wire_type,
        auth=outer.identity.auth,
    )


class _ReadOnlyDiscoveryProtocol:
    """Collect the first matching reply without retaining packet contents."""

    def __init__(
        self,
        expected_host: str,
        expected_mac: bytes,
        wire_types: set[int],
        sequences: set[int],
    ) -> None:
        self._expected_host = expected_host
        self._expected_mac = expected_mac
        self._wire_types = wire_types
        self._sequences = sequences
        self.result: DiscoveryResult | None = None
        self.response_received = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.result is not None:
            return
        result = _decode_reply(data, addr, self._expected_mac, self._sequences)
        if result is None:
            result = _decode_passive_status(
                data,
                addr,
                self._expected_host,
                self._expected_mac,
                self._wire_types,
            )
        if result is not None:
            self.result = result
            self.response_received.set()


async def async_discover_device(
    host: str,
    mac: str | bytes,
    wire_types: tuple[int, ...] = (1, 2, 3, 4),
    *,
    response_timeout: float = DISCOVERY_TIMEOUT_SECONDS,
    passive_timeout: float = DISCOVERY_PASSIVE_TIMEOUT_SECONDS,
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
        (0x002A + index) & 0xFFFF
        for index, _wire_type in enumerate(selected_wire_types)
    }
    protocol = _ReadOnlyDiscoveryProtocol(
        str(parsed_host), target_mac, set(selected_wire_types), sequences
    )
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
                sequence = (0x002A + index) & 0xFFFF
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
        except TimeoutError:
            if passive_timeout <= 0:
                raise DiscoveryTimeoutError from None
            try:
                await asyncio.wait_for(
                    protocol.response_received.wait(), timeout=passive_timeout
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
