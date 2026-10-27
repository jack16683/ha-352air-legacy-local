# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the independent legacy and 352Life LAN discovery mechanisms together."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import socket
from collections import Counter
from collections.abc import Awaitable
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from .const import (
    NETWORK_DISCOVERY_RETRY_INTERVAL_SECONDS,
    NETWORK_DISCOVERY_TIMEOUT_SECONDS,
    normalize_mac,
)
from .discovery import (
    DiscoveryError,
    DiscoveryResult,
    DiscoveryTimeoutError,
)
from .discovery import (
    async_discover_device as async_discover_legacy_device,
)
from .discovery import (
    async_discover_devices as async_discover_legacy_devices,
)
from .protocols.coap_discovery import (
    ALCS_MULTICAST,
    COAP_PORT,
    DISCOVERY_METHODS,
    MAX_DEVICES,
    LocalIdentity,
    decode_identities,
    decode_response,
    encode_ack,
    encode_discovery_request,
)
from .protocols.discovery import DISCOVERY_COMPANY

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
type LocalResult = DiscoveryResult | LocalIdentity
_SETTLE_SECONDS = 0.3


@dataclass(frozen=True, slots=True)
class ScanInterface:
    """An enabled IPv4 interface and its subnet's broadcast destination."""

    address: str
    broadcast: str


async def async_scan_interfaces(hass: HomeAssistant) -> tuple[ScanInterface, ...]:
    """Respect the user's HA network adapter selection."""
    from homeassistant.components import network  # noqa: PLC0415

    interfaces: dict[str, ScanInterface] = {}
    for adapter in await network.async_get_adapters(hass):
        if not adapter["enabled"]:
            continue
        for info in adapter["ipv4"]:
            try:
                interface = ipaddress.IPv4Interface(
                    f"{info['address']}/{info['network_prefix']}"
                )
            except (KeyError, ValueError):
                continue
            if interface.ip.is_loopback or interface.ip.is_unspecified:
                continue
            if interface.network.prefixlen >= 31:
                continue
            interfaces[str(interface.ip)] = ScanInterface(
                str(interface.ip), str(interface.network.broadcast_address)
            )
    return tuple(interfaces.values())


def result_id(result: LocalResult) -> str:
    """Keep existing legacy unique IDs stable."""
    return result.unique_id if isinstance(result, LocalIdentity) else result.mac


class _CoapDiscoveryProtocol(asyncio.DatagramProtocol):
    """Receive only correlated discovery replies, retaining safe identity fields."""

    def __init__(
        self,
        results: dict[str, LocalIdentity],
        found: asyncio.Event,
        excluded_ids: frozenset[str],
        host: str | None,
        mac: str | None,
        required_identity: str | None = None,
    ) -> None:
        self.results = results
        self.found = found
        self.excluded_ids = excluded_ids
        self.host = host
        self.mac = mac
        self.required_identity = required_identity
        self.requests: dict[bytes, tuple[str, str]] = {}
        self.transport: asyncio.DatagramTransport | None = None
        self.received = 0
        self.rejected = 0
        self.probes = 0
        self.send_errors = 0
        self.rejections: Counter[str] = Counter()
        self.accepted: Counter[str] = Counter()

    def _reject(self, reason: str) -> None:
        self.rejected += 1
        self.rejections[reason] += 1

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def error_received(self, _exc: Exception) -> None:
        self.send_errors += 1

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received += 1
        if addr[1] != COAP_PORT or (self.host is not None and addr[0] != self.host):
            self._reject("source")
            return
        response = decode_response(data)
        if response is None:
            self._reject("coap_envelope")
            return
        if response.token not in self.requests:
            self._reject("request_token")
            return
        mechanism, request_id = self.requests[response.token]
        identities = decode_identities(response.payload, addr[0], mechanism, request_id)
        if response.confirmable and self.transport is not None:
            with suppress(OSError):
                self.transport.sendto(encode_ack(response), addr)
        if not identities:
            self._reject("identity_payload")
        for identity in identities:
            if (
                identity.unique_id in self.excluded_ids
                or identity.mac in self.excluded_ids
                or (
                    self.required_identity is not None
                    and identity.unique_id != self.required_identity
                )
                or (
                    self.mac is not None
                    and identity.mac is not None
                    and identity.mac != self.mac
                )
            ):
                continue
            if (
                len(self.results) >= MAX_DEVICES
                and identity.unique_id not in self.results
            ):
                continue
            previous = self.results.get(identity.unique_id)
            # Device-info includes optional MAC/firmware that ALCS may omit.
            self.results[identity.unique_id] = (
                identity
                if previous is None
                else replace(
                    identity,
                    mac=identity.mac or previous.mac,
                    firmware=identity.firmware or previous.firmware,
                )
            )
            self.accepted[mechanism] += 1
            self.found.set()

    def send_round(self, interface: ScanInterface) -> None:
        """Both mechanisms are sent before considering an early result."""
        assert self.transport is not None
        for mechanism in DISCOVERY_METHODS:
            target = self.host or (
                interface.broadcast if mechanism == "device_info" else ALCS_MULTICAST
            )
            token = secrets.token_bytes(8)
            request_id = str(secrets.randbits(32))
            self.requests[token] = (mechanism, request_id)
            packet = encode_discovery_request(
                mechanism, token, secrets.randbits(16), request_id
            )
            try:
                self.transport.sendto(packet, (target, COAP_PORT))
            except OSError:
                self.send_errors += 1
            else:
                self.probes += 1


async def async_discover_coap_devices(
    *,
    interfaces: tuple[ScanInterface, ...],
    host: str | None = None,
    mac: str | None = None,
    excluded_ids: frozenset[str] = frozenset(),
    response_timeout: float = NETWORK_DISCOVERY_TIMEOUT_SECONDS,
    retry_interval: float = NETWORK_DISCOVERY_RETRY_INTERVAL_SECONDS,
    required_identity: str | None = None,
) -> tuple[LocalIdentity, ...]:
    """Send device-info broadcasts and ALCS multicast GETs on enabled adapters."""
    if response_timeout <= 0 or retry_interval <= 0:
        raise DiscoveryError("Discovery timeout and retry interval must be positive")
    if host is not None:
        host = str(ipaddress.IPv4Address(host))
    if mac:
        mac = normalize_mac(mac)
    loop = asyncio.get_running_loop()
    found = asyncio.Event()
    results: dict[str, LocalIdentity] = {}
    endpoints: list[tuple[_CoapDiscoveryProtocol, ScanInterface]] = []
    _LOGGER.debug(
        "Local CoAP discovery start interfaces=%d directed=%s",
        len(interfaces),
        host is not None,
    )
    try:
        for interface in interfaces:
            protocol = _CoapDiscoveryProtocol(
                results, found, excluded_ids, host, mac, required_identity
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface.address),
                )
                # CoAP responses echo the request token to its source endpoint;
                # unlike legacy 352, a fixed source port is not required.
                sock.bind((interface.address, 0))
                await loop.create_datagram_endpoint(lambda p=protocol: p, sock=sock)
            except OSError:
                sock.close()
                _LOGGER.debug("Local CoAP discovery interface could not be opened")
                continue
            except BaseException:
                if protocol.transport is not None:
                    protocol.transport.close()
                sock.close()
                raise
            endpoints.append((protocol, interface))
        if not endpoints:
            return ()
        deadline = loop.time() + response_timeout
        while True:
            for protocol, interface in endpoints:
                protocol.send_round(interface)
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(found.wait(), min(retry_interval, remaining))
            except TimeoutError:
                if loop.time() >= deadline:
                    break
            else:
                # Keep the endpoint briefly for the other mechanism's response.
                await asyncio.sleep(
                    min(_SETTLE_SECONDS, max(0, deadline - loop.time()))
                )
                break
        return tuple(results[key] for key in sorted(results))
    finally:
        rejections: Counter[str] = Counter()
        accepted: Counter[str] = Counter()
        for protocol, _interface in endpoints:
            rejections.update(protocol.rejections)
            accepted.update(protocol.accepted)
            if protocol.transport is not None:
                protocol.transport.close()
        _LOGGER.debug(
            "Local CoAP discovery finished probes=%d received=%d rejected=%d "
            "devices=%d send_errors=%d rejections=%s accepted=%s",
            sum(p.probes for p, _ in endpoints),
            sum(p.received for p, _ in endpoints),
            sum(p.rejected for p, _ in endpoints),
            len(results),
            sum(p.send_errors for p, _ in endpoints),
            dict(rejections),
            dict(accepted),
        )


async def _race_discovery(
    legacy: Awaitable[tuple[DiscoveryResult, ...]],
    modern: Awaitable[tuple[LocalIdentity, ...]],
) -> tuple[LocalResult, ...]:
    """One failing/empty protocol must not hide another protocol's replies."""
    tasks = {
        asyncio.create_task(legacy, name="352air legacy setup discovery"),
        asyncio.create_task(modern, name="352air CoAP setup discovery"),
    }
    results: dict[str, LocalResult] = {}
    pending = tasks.copy()
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    found = task.result()
                except (DiscoveryError, OSError):
                    _LOGGER.debug("One local discovery mechanism was unavailable")
                    continue
                for result in found:
                    results[result_id(result)] = result
            if results:
                # Let other initial sends finish and collect nearly simultaneous
                # responses, rather than waiting out an unrelated 45-second scan.
                if pending:
                    done, pending = await asyncio.wait(pending, timeout=_SETTLE_SECONDS)
                    for task in done:
                        try:
                            for result in task.result():
                                results[result_id(result)] = result
                        except (DiscoveryError, OSError):
                            _LOGGER.debug("Another local discovery mechanism failed")
                break
        legacy_macs = {
            result.mac
            for result in results.values()
            if isinstance(result, DiscoveryResult)
        }
        # Prefer a proven legacy control path if the same MAC answers both.
        return tuple(
            result
            for result in results.values()
            if not isinstance(result, LocalIdentity) or result.mac not in legacy_macs
        )
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def async_discover_devices(
    *,
    interfaces: tuple[ScanInterface, ...],
    excluded_macs: frozenset[str] = frozenset(),
    response_timeout: float = NETWORK_DISCOVERY_TIMEOUT_SECONDS,
) -> tuple[LocalResult, ...]:
    """Try every implemented LAN mechanism, filtering configured identities."""
    return await _race_discovery(
        async_discover_legacy_devices(
            response_timeout=response_timeout,
            excluded_macs=excluded_macs,
            targets=tuple(dict.fromkeys(i.broadcast for i in interfaces)),
        ),
        async_discover_coap_devices(
            interfaces=interfaces,
            excluded_ids=excluded_macs,
            response_timeout=response_timeout,
        ),
    )


async def async_discover_device(
    host: str,
    mac: str | None = None,
    wire_types: tuple[int, ...] = (1, 2, 3, 4),
    *,
    interfaces: tuple[ScanInterface, ...],
    company: int = DISCOVERY_COMPANY,
    auth: int | None = None,
    compatibility_probes: bool = True,
    response_timeout: float = NETWORK_DISCOVERY_TIMEOUT_SECONDS,
) -> LocalResult:
    """Probe a known IP with legacy and both CoAP mechanisms."""
    host = str(ipaddress.IPv4Address(host))
    if not interfaces:
        raise DiscoveryError("No enabled IPv4 discovery interface")
    if mac:
        mac = normalize_mac(mac)

    async def legacy() -> tuple[DiscoveryResult, ...]:
        if mac:
            result = await async_discover_legacy_device(
                host,
                mac,
                wire_types,
                company=company,
                auth=auth,
                compatibility_probes=compatibility_probes,
                broadcast_targets=tuple(i.broadcast for i in interfaces),
                response_timeout=min(4, response_timeout),
                passive_timeout=max(0, response_timeout - 4),
            )
            return (result,)
        return await async_discover_legacy_devices(
            targets=(host,),
            expected_host=host,
            response_timeout=response_timeout,
        )

    results = await _race_discovery(
        legacy(),
        async_discover_coap_devices(
            interfaces=interfaces,
            host=host,
            mac=mac,
            response_timeout=response_timeout,
        ),
    )
    if not results:
        raise DiscoveryTimeoutError
    if len(results) != 1:
        # Do not silently choose one identity behind a shared gateway IP.
        raise DiscoveryError("Multiple device identities replied at this address")
    return results[0]
