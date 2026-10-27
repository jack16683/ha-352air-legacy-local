# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only UDP discovery for legacy 352 devices.

Discovery and optional type-2 state queries are read-only. No control,
provisioning, or lock packet is sent, and an identity is never accepted
without a validated response from the configured address and MAC.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections import Counter
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from time import monotonic_ns

from .const import (
    DISCOVERY_PASSIVE_TIMEOUT_SECONDS,
    DISCOVERY_TIMEOUT_SECONDS,
    NETWORK_DISCOVERY_RETRY_INTERVAL_SECONDS,
    NETWORK_DISCOVERY_TIMEOUT_SECONDS,
    UDP_PORT,
    mac_to_bytes,
    normalize_mac,
)
from .models import CommandContext, HeaderIdentity
from .protocols.a5a0 import A5A0Codec
from .protocols.base import (
    f072_response_crc_is_valid,
    ignore_rejection,
    parse_outer_frame,
)
from .protocols.discovery import (
    DISCOVERY_AUTH,
    DISCOVERY_COMPANY,
    decode_discovery_reply,
    encode_discovery_probe,
)
from .udp import async_acquire_udp_endpoint, async_release_udp_endpoint

_LOGGER = logging.getLogger(__name__)


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
    *,
    on_reject: Callable[[str], None] = ignore_rejection,
) -> DiscoveryResult | None:
    """Validate the small discovery subset needed to learn a header identity."""
    decoded = decode_discovery_reply(datagram, source, on_reject=on_reject)
    if decoded is None:
        return None
    if decoded.identity.mac != expected_mac:
        on_reject("target_mac_mismatch")
        return None
    if sequences and decoded.sequence not in sequences:
        on_reject("sequence_mismatch")
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
    *,
    on_reject: Callable[[str], None] = ignore_rejection,
) -> DiscoveryResult | None:
    """Learn identity from a strictly validated, non-mutating state broadcast."""
    if source != (expected_host, UDP_PORT):
        on_reject("source_mismatch")
        return None
    outer = parse_outer_frame(datagram, on_reject=on_reject)
    if outer is None:
        return None
    if outer.operation != 0x04:
        on_reject("state_operation")
        return None
    if outer.identity.mac != expected_mac:
        on_reject("target_mac_mismatch")
        return None
    if outer.identity.wire_type not in wire_types:
        on_reject("state_wire_type")
        return None

    payload = outer.payload
    wire_type = outer.identity.wire_type
    valid_state = False
    if wire_type == 1:
        valid_state = (
            len(payload) == 17
            and payload[0] in {0x03, 0x04}
            and payload[1] == 0xF5
            and payload[2] in {0xA1, 0xA2}
        )
    elif wire_type == 2:
        valid_state = (
            len(payload) in {33, 65}
            and payload[:3] == b"\x02\x5a\xa1"
            and (len(payload) == 33 or payload[33:35] == b"\x5a\xa1")
        )
    elif wire_type in {3, 4} and len(payload) >= 16 and payload[0] in {0x01, 0x02}:
        frame = payload[1:]
        minimum_data_length = 30 if wire_type == 3 else 29
        # Match the runtime decoder: removing the route moves the response
        # marker/type/data from payload 6/7/8 to frame 5/6/7.
        valid_state = (
            len(frame) >= minimum_data_length + 9
            and frame[:2] == b"\xf0\x72"
            and frame[5] in {0x84, 0x03}
            and frame[6] == 0x02
        )
        if valid_state and not f072_response_crc_is_valid(frame):
            on_reject("state_crc")
            return None
    if not valid_state:
        on_reject("state_payload_layout")
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
        self.received = 0
        self.target_received = 0
        self.probes = 0
        self.send_errors = 0
        self.phase = "active"
        self.accepted = "none"
        self.discovery_rejections: Counter[str] = Counter()
        self.state_rejections: Counter[str] = Counter()
        self.result: DiscoveryResult | None = None
        self.response_received = asyncio.Event()

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.result is not None:
            return
        self.received += 1
        is_target = addr[0] == self._expected_host
        if is_target:
            self.target_received += 1
        else:
            return
        # Shared endpoint traffic from other devices must not obscure the target.
        result = _decode_reply(
            data,
            addr,
            self._expected_mac,
            self._sequences,
            on_reject=self._reject_discovery if is_target else ignore_rejection,
        )
        accepted = "discovery_reply"
        if result is not None and result.wire_type not in self._wire_types:
            self._reject_discovery("discovery_wire_type")
            result = None
        if result is None:
            accepted = "passive_state"
            result = _decode_passive_status(
                data,
                addr,
                self._expected_host,
                self._expected_mac,
                self._wire_types,
                on_reject=self._reject_state if is_target else ignore_rejection,
            )
        if result is not None:
            self.accepted = accepted
            self.result = result
            self.response_received.set()

    def _reject_discovery(self, reason: str) -> None:
        self.discovery_rejections[reason] += 1

    def _reject_state(self, reason: str) -> None:
        self.state_rejections[reason] += 1

    def log_summary(self, outcome: str) -> None:
        """Log only counts and fixed labels, never device or packet contents."""
        _LOGGER.debug(
            "Discovery diagnostics outcome=%s phase=%s probes=%d received=%d "
            "target_received=%d other_received=%d accepted=%s send_errors=%d "
            "discovery_rejections=%s state_rejections=%s",
            outcome,
            self.phase,
            self.probes,
            self.received,
            self.target_received,
            self.received - self.target_received,
            self.accepted,
            self.send_errors,
            dict(self.discovery_rejections),
            dict(self.state_rejections),
        )


class _ReadOnlyNetworkDiscoveryProtocol:
    """Collect validated discovery replies and state broadcasts from the LAN."""

    def __init__(
        self,
        sequences: set[int],
        excluded_macs: frozenset[str] = frozenset(),
        expected_host: str | None = None,
        expected_mac: str | None = None,
    ) -> None:
        self.sequences = sequences
        self.excluded_macs = excluded_macs
        self.results: dict[str, DiscoveryResult] = {}
        self.response_received = asyncio.Event()
        self.received = 0
        self.probes = 0
        self.send_errors = 0
        self.expected_host = expected_host
        self.expected_mac = expected_mac

    def datagram_received(self, data: bytes, source: tuple[str, int]) -> None:
        self.received += 1
        if self.expected_host is not None and source[0] != self.expected_host:
            return
        outer = parse_outer_frame(data)
        if (
            outer is None
            or source[1] != UDP_PORT
            or outer.identity.wire_type not in {1, 2, 3, 4}
            or outer.identity.mac in {bytes(6), b"\xff" * 6}
        ):
            return
        decoded = decode_discovery_reply(data, source)
        if decoded is not None and decoded.sequence in self.sequences:
            result = DiscoveryResult(
                decoded.host,
                normalize_mac(decoded.identity.mac),
                decoded.identity.company,
                decoded.identity.wire_type,
                decoded.identity.auth,
            )
        else:
            result = _decode_passive_status(
                data, source, source[0], outer.identity.mac, {1, 2, 3, 4}
            )
        if result is not None and result.mac in self.excluded_macs:
            return
        if (
            result is not None
            and self.expected_mac is not None
            and result.mac != self.expected_mac
        ):
            return
        if result is not None and (
            result.mac in self.results or len(self.results) < 64
        ):
            self.results[result.mac] = result
            self.response_received.set()


async def async_discover_devices(
    *,
    response_timeout: float = NETWORK_DISCOVERY_TIMEOUT_SECONDS,
    retry_interval: float = NETWORK_DISCOVERY_RETRY_INTERVAL_SECONDS,
    excluded_macs: frozenset[str] = frozenset(),
    targets: tuple[str, ...] = ("255.255.255.255",),
    expected_host: str | None = None,
    expected_mac: str | None = None,
) -> tuple[DiscoveryResult, ...]:
    """Search read-only until an eligible device replies or the window expires."""
    if response_timeout <= 0 or retry_interval <= 0:
        raise DiscoveryError("Discovery timeout and retry interval must be positive")
    if not targets:
        raise DiscoveryError("No enabled IPv4 discovery interface")
    targets = tuple(dict.fromkeys(str(ipaddress.IPv4Address(t)) for t in targets))
    first_sequence = monotonic_ns() & 0xFFFF
    sequences = {(first_sequence + offset) & 0xFFFF for offset in range(4)}
    protocol = _ReadOnlyNetworkDiscoveryProtocol(
        sequences, excluded_macs, expected_host, expected_mac
    )
    endpoint = None
    resend_task: asyncio.Task[None] | None = None
    outcome = "interrupted"
    _LOGGER.debug(
        "Network discovery start response_timeout=%s retry_interval=%s excluded=%d",
        response_timeout,
        retry_interval,
        len(excluded_macs),
    )
    try:
        try:
            endpoint = await async_acquire_udp_endpoint(protocol.datagram_received)
        except OSError as err:
            outcome = "endpoint_error"
            raise DiscoveryError("Unable to bind local UDP port 11530") from err

        def send_probes() -> None:
            assert endpoint is not None
            for offset, wire_type in enumerate((1, 2, 3, 4)):
                for operation in (0x00, 0x04):
                    if protocol.response_received.is_set():
                        return
                    packet = encode_discovery_probe(
                        b"\xff" * 6,
                        wire_type,
                        (first_sequence + offset) & 0xFFFF,
                        operation=operation,
                    )
                    for target in targets:
                        try:
                            endpoint.sendto(packet, (target, UDP_PORT))
                        except OSError:
                            protocol.send_errors += 1
                        else:
                            protocol.probes += 1

        deadline = asyncio.get_running_loop().time() + response_timeout

        async def resend_probes() -> None:
            while True:
                await asyncio.sleep(retry_interval)
                if (
                    protocol.response_received.is_set()
                    or asyncio.get_running_loop().time() >= deadline
                ):
                    return
                send_probes()

        send_probes()
        resend_task = asyncio.create_task(
            resend_probes(), name="352air read-only network discovery retry"
        )
        with suppress(TimeoutError):
            await asyncio.wait_for(
                protocol.response_received.wait(), timeout=response_timeout
            )
        outcome = "success" if protocol.results else "no_devices"
        return tuple(protocol.results[key] for key in sorted(protocol.results))
    finally:
        if resend_task is not None and not resend_task.done():
            resend_task.cancel()
            with suppress(asyncio.CancelledError):
                await resend_task
        if endpoint is not None:
            await async_release_udp_endpoint(endpoint, protocol.datagram_received)
        _LOGGER.debug(
            "Network discovery outcome=%s probes=%d received=%d devices=%d "
            "send_errors=%d",
            outcome,
            protocol.probes,
            protocol.received,
            len(protocol.results),
            protocol.send_errors,
        )


async def async_discover_device(
    host: str,
    mac: str | bytes,
    wire_types: tuple[int, ...] = (1, 2, 3, 4),
    *,
    response_timeout: float = DISCOVERY_TIMEOUT_SECONDS,
    passive_timeout: float = DISCOVERY_PASSIVE_TIMEOUT_SECONDS,
    company: int = DISCOVERY_COMPANY,
    auth: int | None = None,
    compatibility_probes: bool = False,
    broadcast_targets: tuple[str, ...] = ("255.255.255.255",),
) -> DiscoveryResult:
    """Probe a known address/MAC with only documented read-only packets.

    Runtime and discovery share one local UDP 11530 endpoint because these
    devices reply to that fixed port rather than the request's source port.
    """
    parsed_host = ipaddress.ip_address(host)
    if parsed_host.version != 4:
        raise DiscoveryError("Only IPv4 addresses are supported")
    broadcast_targets = tuple(
        dict.fromkeys(str(ipaddress.IPv4Address(t)) for t in broadcast_targets)
    )

    target_mac = mac_to_bytes(mac)
    probe_auth = DISCOVERY_AUTH if auth is None else auth
    selected_wire_types = tuple(dict.fromkeys(wire_types))
    if not selected_wire_types or any(
        wire_type not in range(1, 5) for wire_type in selected_wire_types
    ):
        raise DiscoveryError("Unsupported discovery wire type")
    # Validate imported header values before opening the shared endpoint.
    HeaderIdentity(target_mac, company, selected_wire_types[0], probe_auth)

    sequences = {
        (0x002A + index) & 0xFFFF
        for index, _wire_type in enumerate(selected_wire_types)
    }
    protocol = _ReadOnlyDiscoveryProtocol(
        str(parsed_host), target_mac, set(selected_wire_types), sequences
    )
    _LOGGER.debug(
        "Discovery diagnostics start wire_types=%s "
        "active_timeout=%s passive_timeout=%s compatibility=%s imported_auth=%s",
        selected_wire_types,
        response_timeout,
        passive_timeout,
        compatibility_probes,
        auth is not None,
    )
    outcome = "interrupted"
    endpoint = None
    resend_task: asyncio.Task[None] | None = None
    try:
        try:
            endpoint = await async_acquire_udp_endpoint(protocol.datagram_received)
        except OSError as err:
            protocol.phase = "bind"
            outcome = "endpoint_error"
            raise DiscoveryError("Unable to bind local UDP port 11530") from err

        def send_probe(packet: bytes, target: tuple[str, int]) -> None:
            """Keep unavailable routes from interrupting passive discovery."""
            assert endpoint is not None
            try:
                endpoint.sendto(packet, target)
            except OSError:
                protocol.send_errors += 1
            else:
                protocol.probes += 1

        def send_probes() -> None:
            for index, wire_type in enumerate(selected_wire_types):
                sequence = (0x002A + index) & 0xFFFF
                send_probe(
                    encode_discovery_probe(
                        target_mac,
                        wire_type,
                        sequence,
                        company=company,
                        auth=probe_auth,
                    ),
                    (str(parsed_host), UDP_PORT),
                )
            _LOGGER.debug(
                "Discovery diagnostics probes_sent=%d phase=%s",
                protocol.probes,
                protocol.phase,
            )

        def send_compatibility_probes() -> None:
            """Try bounded, documented reads; credentials are only probe seeds."""
            assert endpoint is not None
            if 2 not in selected_wire_types:
                return
            sequence = (0x002A + selected_wire_types.index(2)) & 0xFFFF
            # These two historical credentials are hypotheses for reads only.
            # Persisted control identity always comes from the device response.
            candidates = (probe_auth, 0x0403, 0x0504) if auth is None else (probe_auth,)
            for candidate in dict.fromkeys(candidates):
                if protocol.response_received.is_set():
                    break
                directed = encode_discovery_probe(
                    target_mac, 2, sequence, company=company, auth=candidate
                )
                broadcast = encode_discovery_probe(
                    b"\xff" * 6, 2, sequence, company=company, auth=candidate
                )
                identity = HeaderIdentity(target_mac, company, 2, candidate)
                query = A5A0Codec().encode_query(CommandContext(identity, sequence))
                packets = (
                    (directed, (str(parsed_host), UDP_PORT)),
                    *((directed, (target, UDP_PORT)) for target in broadcast_targets),
                    *((broadcast, (target, UDP_PORT)) for target in broadcast_targets),
                    (query, (str(parsed_host), UDP_PORT)),
                )
                for packet, target in packets:
                    if protocol.response_received.is_set():
                        break
                    send_probe(packet, target)
            _LOGGER.debug(
                "Discovery diagnostics compatibility_probes_sent=%d phase=%s",
                protocol.probes,
                protocol.phase,
            )

        async def resend_probes() -> None:
            await asyncio.sleep(min(0.75, response_timeout / 3))
            if not protocol.response_received.is_set():
                send_probes()
                if compatibility_probes:
                    send_compatibility_probes()
                    # The app repeats discovery every five seconds. Continue
                    # during passive listening, stopping promptly on success.
                    for _ in range(2):
                        await asyncio.sleep(5)
                        if protocol.response_received.is_set():
                            return
                        send_compatibility_probes()

        send_probes()
        resend_task = asyncio.create_task(
            resend_probes(), name="352air read-only discovery retry"
        )
        try:
            await asyncio.wait_for(
                protocol.response_received.wait(), timeout=response_timeout
            )
        except TimeoutError:
            protocol.log_summary("active_timeout")
            if passive_timeout <= 0:
                outcome = "timeout"
                raise DiscoveryTimeoutError from None
            protocol.phase = "passive"
            _LOGGER.debug("Discovery diagnostics entering passive wait")
            try:
                await asyncio.wait_for(
                    protocol.response_received.wait(), timeout=passive_timeout
                )
            except TimeoutError as err:
                outcome = "timeout"
                raise DiscoveryTimeoutError from err

        if protocol.result is None:
            outcome = "timeout"
            raise DiscoveryTimeoutError
        outcome = "success"
        return protocol.result
    finally:
        protocol.log_summary(outcome)
        if resend_task is not None and not resend_task.done():
            resend_task.cancel()
            with suppress(asyncio.CancelledError):
                await resend_task
        if endpoint is not None:
            await async_release_udp_endpoint(endpoint, protocol.datagram_received)
