# SPDX-License-Identifier: GPL-3.0-or-later
"""One shared UDP 11530 endpoint for discovery and configured devices."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from weakref import WeakKeyDictionary

_LOGGER = logging.getLogger(__name__)

DatagramCallback = Callable[[bytes, tuple[str, int]], None]
_EndpointKey = tuple[str, int]


class SharedUdpEndpoint:
    """A reference-counted socket shared by consumers on one event loop."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        key: _EndpointKey,
        transport: asyncio.DatagramTransport,
    ) -> None:
        self.loop = loop
        self.key = key
        self._transport = transport
        self._callbacks: set[DatagramCallback] = set()
        self._references = 0

    def sendto(self, data: bytes, target: tuple[str, int]) -> None:
        """Send through the fixed local port that receives device replies."""
        self._transport.sendto(data, target)

    def _dispatch(self, data: bytes, addr: tuple[str, int]) -> None:
        for callback in tuple(self._callbacks):
            try:
                callback(data, addr)
            except Exception:  # A consumer must not break delivery to others.
                _LOGGER.exception("352 UDP datagram subscriber failed")


class _DeferredProtocol(asyncio.DatagramProtocol):
    """Bridge endpoint construction to asyncio's synchronous factory call."""

    endpoint: SharedUdpEndpoint | None = None

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.endpoint is not None:
            self.endpoint._dispatch(data, addr)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("Shared 352 UDP receive error: %s", type(exc).__name__)


_ENDPOINTS: WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[_EndpointKey, SharedUdpEndpoint]
] = WeakKeyDictionary()
_LOCKS: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = WeakKeyDictionary()


def _loop_lock(loop: asyncio.AbstractEventLoop) -> asyncio.Lock:
    lock = _LOCKS.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[loop] = lock
    return lock


async def async_acquire_udp_endpoint(
    callback: DatagramCallback,
    *,
    bind_host: str = "0.0.0.0",
    port: int = 11530,
) -> SharedUdpEndpoint:
    """Acquire the loop-local UDP endpoint and subscribe to its datagrams."""
    loop = asyncio.get_running_loop()
    key = (bind_host, port)
    async with _loop_lock(loop):
        endpoints = _ENDPOINTS.setdefault(loop, {})
        endpoint = endpoints.get(key)
        if endpoint is None:
            protocol = _DeferredProtocol()
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: protocol,
                    local_addr=key,
                    allow_broadcast=True,
                )
            except OSError:
                if port == 0:
                    raise
                # Some firmware replies to the source port while the tested
                # X83C replies to 11530. This fallback can help the former,
                # but the fixed port remains the preferred reliable path.
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: protocol,
                    local_addr=(bind_host, 0),
                    allow_broadcast=True,
                )
                _LOGGER.warning(
                    "UDP 11530 is occupied; using a less-compatible ephemeral port"
                )
            endpoint = SharedUdpEndpoint(loop, key, transport)
            protocol.endpoint = endpoint
            endpoints[key] = endpoint
        endpoint._references += 1
        endpoint._callbacks.add(callback)
        return endpoint


async def async_release_udp_endpoint(
    endpoint: SharedUdpEndpoint,
    callback: DatagramCallback,
) -> None:
    """Unsubscribe and close the socket after its last consumer leaves."""
    loop = endpoint.loop
    async with _loop_lock(loop):
        endpoint._callbacks.discard(callback)
        endpoint._references = max(0, endpoint._references - 1)
        if endpoint._references:
            return
        endpoints = _ENDPOINTS.get(loop)
        if endpoints is not None and endpoints.get(endpoint.key) is endpoint:
            del endpoints[endpoint.key]
        endpoint._transport.close()
