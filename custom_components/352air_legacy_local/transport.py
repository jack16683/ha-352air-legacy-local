# SPDX-License-Identifier: GPL-3.0-or-later
"""Asyncio-native local UDP client with validated state confirmation."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field, fields
from typing import Any, Final

from .models import (
    ClientClosedError,
    Command,
    CommandContext,
    CommandOperation,
    DecodedPacket,
    DeviceModel,
    DeviceState,
    DeviceUnavailableError,
    Endpoint,
    HeaderIdentity,
    PacketKind,
    PowerState,
    ProtocolFamily,
    RequestTimeoutError,
    family_for_model,
)
from .protocols import DeviceCodec, F072Codec, codec_for_model
from .udp import (
    SharedUdpEndpoint,
    async_acquire_udp_endpoint,
    async_release_udp_endpoint,
)

_LOGGER = logging.getLogger(__name__)
_DEVICE_PORT: Final = 11530
_DUPLICATE_WINDOW: Final = 3.0
_MAX_RECENT_DATAGRAMS: Final = 512
_INVALID_LOG_INTERVAL: Final = 30.0

StateListener = Callable[[DeviceState], None]
IdentityListener = Callable[[HeaderIdentity], None]


@dataclass(slots=True)
class _PendingState:
    """One response wait, registered before any relevant datagram is sent."""

    future: asyncio.Future[DeviceState]
    outer_sequences: frozenset[int]
    inner_sequences: frozenset[int]
    command: Command | None
    expected_kind: PacketKind
    created_at: float


@dataclass(slots=True)
class _QueuedCommand:
    """An unsent write plus all callers it represents after coalescing."""

    command: Command
    waiters: list[asyncio.Future[DeviceState]] = field(default_factory=list)


class LocalDeviceClient:
    """Long-lived asyncio UDP client for exactly one normalized MAC address.

    The client learns mutable header fields only from validated packets that
    retain the configured MAC.  It intentionally does not contain a Home
    Assistant import or make any cloud/provisioning request.
    """

    def __init__(
        self,
        *,
        host: str,
        identity: HeaderIdentity,
        model: DeviceModel,
        codec: DeviceCodec | None = None,
        port: int = _DEVICE_PORT,
        timeout: float = 5.0,
        bind_host: str = "0.0.0.0",
    ) -> None:
        if not isinstance(host, str) or not host:
            raise ValueError("host must be a non-empty IPv4 or IPv6 address string")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 0xFFFF
        ):
            raise ValueError("port must be in the range 1..65535")
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if codec is None:
            codec = codec_for_model(model)
        if codec.family is not family_for_model(model):
            raise ValueError("codec family does not match the selected device model")

        self.host = host
        self.port = port
        self.model = model
        self.codec = codec
        self.timeout = timeout
        self.bind_host = bind_host
        self._identity = identity
        self._state: DeviceState | None = None
        self._available = False
        self._last_state_at: float | None = None

        self._loop: asyncio.AbstractEventLoop | None = None
        self._lifecycle_lock = asyncio.Lock()
        self._queue_lock = asyncio.Lock()
        self._started = False
        self._closed = False
        self._endpoint: SharedUdpEndpoint | None = None
        self._pending: list[_PendingState] = []
        self._queue: deque[_QueuedCommand] = deque()
        self._worker_task: asyncio.Task[None] | None = None
        self._active_waiters: list[asyncio.Future[DeviceState]] = []
        self._outer_sequence = 0
        self._inner_sequence = 0
        self._recent_datagrams: dict[bytes, float] = {}
        self._state_listeners: list[StateListener] = []
        self._identity_listeners: list[IdentityListener] = []
        self._last_log_at: dict[str, float] = {}

    @property
    def state(self) -> DeviceState | None:
        """The last validated state received from this device."""

        return self._state

    @property
    def identity(self) -> HeaderIdentity:
        """The most recently learned header identity for the configured MAC."""

        return self._identity

    @property
    def available(self) -> bool:
        """Whether at least one validated state has arrived since start."""

        return self._available

    @property
    def last_state_at(self) -> float | None:
        """Monotonic time of the last validated state, for stale-poll policy."""

        return self._last_state_at

    async def start(self) -> None:
        """Subscribe to the process-wide UDP 11530 endpoint."""

        async with self._lifecycle_lock:
            if self._closed:
                raise ClientClosedError("the local device client is closed")
            if self._started:
                return
            self._loop = asyncio.get_running_loop()
            try:
                self._endpoint = await async_acquire_udp_endpoint(
                    self._datagram_received,
                    bind_host=self.bind_host,
                    port=_DEVICE_PORT,
                )
            except OSError as error:
                raise DeviceUnavailableError(
                    "cannot bind shared UDP port 11530"
                ) from error
            self._started = True

    async def close(self) -> None:
        """Resolve all waits, stop the worker, and release every UDP endpoint."""

        worker: asyncio.Task[None] | None
        async with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            self._started = False
            self._fail_pending(ClientClosedError("the local device client was closed"))
            async with self._queue_lock:
                for queued in self._queue:
                    _set_exception_all(
                        queued.waiters,
                        ClientClosedError("the local device client was closed"),
                    )
                self._queue.clear()
                _set_exception_all(
                    self._active_waiters,
                    ClientClosedError("the local device client was closed"),
                )
            worker = self._worker_task
            if worker is not None and not worker.done():
                worker.cancel()
            endpoint = self._endpoint
            self._endpoint = None

        if endpoint is not None:
            await async_release_udp_endpoint(endpoint, self._datagram_received)

        if worker is not None:
            with suppress(asyncio.CancelledError):
                await worker

    async def refresh(self) -> DeviceState:
        """Issue a read-only query and wait for a validated matching state."""

        await self.start()
        context = self._next_context()
        datagrams = [self.codec.encode_query(context)]
        outer_sequences = {context.outer_sequence}
        inner_sequences = {context.inner_sequence}
        if self.codec.family is ProtocolFamily.M25 and hasattr(
            self.codec, "encode_backlight_query"
        ):
            backlight_context = self._next_context()
            datagrams.append(self.codec.encode_backlight_query(backlight_context))
            outer_sequences.add(backlight_context.outer_sequence)
            inner_sequences.add(backlight_context.inner_sequence)
        return await self._send_for_state(
            datagrams=tuple(datagrams),
            outer_sequences=outer_sequences,
            inner_sequences=inner_sequences,
            command=None,
            expected_kind=PacketKind.STATE,
            retries=2,
        )

    async def refresh_if_stale(self, stale_after: float) -> DeviceState | None:
        """Query only when no validated broadcast/state is recent enough."""

        if stale_after <= 0:
            raise ValueError("stale_after must be greater than zero")
        await self.start()
        assert self._loop is not None
        if (
            self._state is not None
            and self._last_state_at is not None
            and self._loop.time() - self._last_state_at < stale_after
        ):
            return self._state
        return await self.refresh()

    async def command(self, command: Command) -> DeviceState:
        """Serialize a write and return only after a confirming valid state."""

        await self.start()
        loop = self._require_loop()
        future: asyncio.Future[DeviceState] = loop.create_future()
        async with self._queue_lock:
            self._raise_if_closed()
            # Coalesce only a trailing, not-yet-sent percentage write.  A
            # power/preset/etc. command always remains an ordering boundary.
            if (
                command.is_coalescible
                and self._queue
                and self._queue[-1].command.is_coalescible
            ):
                queued = self._queue[-1]
                queued.command = command
                queued.waiters.append(future)
            else:
                self._queue.append(_QueuedCommand(command=command, waiters=[future]))
            if self._worker_task is None or self._worker_task.done():
                self._worker_task = loop.create_task(
                    self._command_worker(), name="352air-local-command"
                )
        return await future

    def add_listener(self, callback: StateListener) -> Callable[[], None]:
        """Register a state callback and return an idempotent remover."""

        self._state_listeners.append(callback)

        def remove() -> None:
            with suppress(ValueError):
                self._state_listeners.remove(callback)

        return remove

    def add_identity_listener(self, callback: IdentityListener) -> Callable[[], None]:
        """Observe learned company/type/auth changes for runtime persistence."""

        self._identity_listeners.append(callback)

        def remove() -> None:
            with suppress(ValueError):
                self._identity_listeners.remove(callback)

        return remove

    async def _command_worker(self) -> None:
        try:
            while True:
                async with self._queue_lock:
                    if not self._queue:
                        return
                    queued = self._queue.popleft()
                    self._active_waiters = queued.waiters
                try:
                    state = await self._execute_command(queued.command)
                except asyncio.CancelledError:
                    _set_exception_all(
                        queued.waiters,
                        ClientClosedError("the local device client was closed"),
                    )
                    raise
                except (
                    Exception
                ) as error:  # A caller receives the concrete protocol error.
                    _set_exception_all(queued.waiters, error)
                else:
                    _set_result_all(queued.waiters, state)
                finally:
                    async with self._queue_lock:
                        if self._active_waiters is queued.waiters:
                            self._active_waiters = []
        finally:
            # Close the empty-queue race: a command can be appended after this
            # worker decides to return but before its task becomes done.
            async with self._queue_lock:
                if self._worker_task is asyncio.current_task():
                    self._worker_task = None
                    if self._queue and not self._closed:
                        loop = self._require_loop()
                        self._worker_task = loop.create_task(
                            self._command_worker(),
                            name="352air-local-command",
                        )

    async def _execute_command(self, command: Command) -> DeviceState:
        self._raise_if_closed()
        command_context = self._next_context()
        command_datagram = self.codec.encode_command(command_context, command)
        query_context = self._next_context()
        if command.operation is CommandOperation.BACKLIGHT and hasattr(
            self.codec, "encode_backlight_query"
        ):
            query_datagram = self.codec.encode_backlight_query(query_context)
            expected_kind = PacketKind.BACKLIGHT
        else:
            query_datagram = self.codec.encode_query(query_context)
            expected_kind = PacketKind.STATE
        return await self._send_for_state(
            datagrams=(command_datagram, query_datagram),
            outer_sequences={
                command_context.outer_sequence,
                query_context.outer_sequence,
            },
            inner_sequences={
                command_context.inner_sequence,
                query_context.inner_sequence,
            },
            command=command,
            expected_kind=expected_kind,
            retries=3,
            inter_datagram_delay=0.15,
        )

    async def _send_for_state(
        self,
        *,
        datagrams: tuple[bytes, ...],
        outer_sequences: set[int],
        inner_sequences: set[int],
        command: Command | None,
        expected_kind: PacketKind,
        retries: int = 1,
        inter_datagram_delay: float = 0,
    ) -> DeviceState:
        loop = self._require_loop()
        self._raise_if_closed()
        future: asyncio.Future[DeviceState] = loop.create_future()
        pending = _PendingState(
            future=future,
            outer_sequences=frozenset(outer_sequences),
            inner_sequences=frozenset(inner_sequences),
            command=command,
            expected_kind=expected_kind,
            created_at=loop.time(),
        )
        self._pending.append(pending)
        try:
            attempt_timeout = self.timeout / retries
            last_timeout: asyncio.TimeoutError | None = None
            for _attempt in range(retries):
                for index, datagram in enumerate(datagrams):
                    self._send(datagram)
                    if inter_datagram_delay and index + 1 < len(datagrams):
                        await asyncio.sleep(inter_datagram_delay)
                try:
                    return await asyncio.wait_for(
                        asyncio.shield(future), timeout=attempt_timeout
                    )
                except TimeoutError as error:
                    last_timeout = error
            self._available = False
            raise RequestTimeoutError(
                "no validated confirming state arrived before timeout"
            ) from last_timeout
        finally:
            with suppress(ValueError):
                self._pending.remove(pending)
            if not future.done():
                future.cancel()

    def _send(self, datagram: bytes) -> None:
        self._raise_if_closed()
        if self._endpoint is None:
            raise DeviceUnavailableError("UDP endpoint is not running")
        try:
            self._endpoint.sendto(datagram, (self.host, self.port))
        except (OSError, RuntimeError) as error:
            raise DeviceUnavailableError("unable to send UDP datagram") from error

    def _datagram_received(self, datagram: bytes, source: Endpoint) -> None:
        if self._closed:
            return
        loop = self._loop
        if loop is None:
            return
        now = loop.time()
        self._prune_duplicates(now)
        if datagram in self._recent_datagrams:
            return
        self._recent_datagrams[datagram] = now
        if len(self._recent_datagrams) > _MAX_RECENT_DATAGRAMS:
            oldest = next(iter(self._recent_datagrams))
            del self._recent_datagrams[oldest]
        try:
            packet = self.codec.decode(datagram, source)
        # Malformed LAN traffic must never tear down the shared UDP endpoint.
        except Exception as error:
            self._rate_limited_debug(
                "decode_error", "Ignoring invalid local UDP packet: %s", error
            )
            return
        if packet is None:
            self._rate_limited_debug(
                "invalid_packet", "Ignoring unrelated or invalid local UDP packet"
            )
            return
        if packet.identity.mac != self._identity.mac:
            self._rate_limited_debug(
                "other_device", "Ignoring UDP packet for a different device MAC"
            )
            return
        self._learn_identity(packet.identity)
        if source[0] != self.host:
            self.host = source[0]
        if packet.state is None:
            return

        merged_state = (
            _merge_state(self._state, packet.state)
            if packet.family is ProtocolFamily.M25
            else packet.state
        )
        self._state = merged_state
        self._available = True
        self._last_state_at = now
        # Datagram callbacks execute in the asyncio loop, and no internal lock
        # is held while invoking user callbacks.
        for callback in tuple(self._state_listeners):
            try:
                callback(merged_state)
            except Exception as error:  # One listener must not stop state delivery.
                self._rate_limited_debug(
                    "state_listener", "State listener failed: %s", error
                )
        self._resolve_matching_pending(packet, merged_state, now)

    def _resolve_matching_pending(
        self,
        packet: DecodedPacket,
        merged_state: DeviceState,
        received_at: float,
    ) -> None:
        assert packet.state is not None
        outer_operation = packet.raw_metadata.get("outer_operation")
        is_broadcast = outer_operation == 0x06
        for pending in tuple(self._pending):
            if pending.future.done() or received_at < pending.created_at:
                continue
            if packet.kind is not pending.expected_kind:
                continue
            matched_sequence = packet.sequence in pending.outer_sequences
            matched_inner_sequence = (
                packet.inner_sequence is not None
                and packet.inner_sequence in pending.inner_sequences
            )
            if not (matched_sequence or matched_inner_sequence or is_broadcast):
                continue
            if pending.command is not None and not self._state_confirms_command(
                merged_state, pending.command
            ):
                continue
            pending.future.set_result(merged_state)

    def _state_confirms_command(self, state: DeviceState, command: Command) -> bool:
        """Require the relevant decoded field when the spec documents one."""

        operation = command.operation
        if operation is CommandOperation.MODE:
            return state.mode is not None and int(state.mode) == command.value
        if operation is CommandOperation.SPEED:
            return state.speed == command.value
        if operation is CommandOperation.PTC:
            # G30/G45 expose a confirmed PTC state. A5A0/X50 only provide a
            # documented command builder, so a fresh valid state is the
            # strongest acknowledgement those experimental controls permit.
            return state.ptc == command.value if state.ptc is not None else True
        if operation is CommandOperation.TIMER:
            return state.timer_hours == command.value
        if operation is CommandOperation.CHILD_LOCK:
            expected = command.value == (
                0x11 if self.codec.family is ProtocolFamily.A5A0 else 0x00
            )
            return state.child_lock is expected
        if operation is CommandOperation.DISPLAY:
            return state.display_on is (command.value == 0x00)
        if operation is CommandOperation.POWER:
            expected_power = (
                PowerState.ON
                if command.value
                == (0x35 if self.codec.family is ProtocolFamily.A5A0 else 0x00)
                else PowerState.OFF
            )
            return state.power is expected_power
        if operation is CommandOperation.AIRFLOW:
            return state.airflow_m3h == command.value
        if operation is CommandOperation.PERCENTAGE:
            if command.value == 0:
                return state.power is PowerState.OFF
            if isinstance(self.codec, F072Codec):
                expected_flow = self.codec.flow_for_percentage(
                    command.value, self._preview_context()
                )
                return state.airflow_m3h == expected_flow
            return False
        if operation is CommandOperation.BACKLIGHT:
            return state.backlight == command.value
        # Filter-operation and M25 backlight response layouts have no documented
        # field that proves the requested value.  A fresh validated state is the
        # strongest non-optimistic confirmation the evidence permits.
        return True

    def _next_context(self) -> CommandContext:
        outer_sequence = self._outer_sequence
        inner_sequence = self._inner_sequence
        self._outer_sequence = (outer_sequence + 1) & 0xFFFF
        self._inner_sequence = (inner_sequence + 1) & 0xFFFF
        return CommandContext(
            identity=self._identity,
            outer_sequence=outer_sequence,
            inner_sequence=inner_sequence,
            model=self.model,
        )

    def _preview_context(self) -> CommandContext:
        """Build a context for deterministic percentage confirmation only."""

        return CommandContext(
            identity=self._identity,
            outer_sequence=0,
            inner_sequence=0,
            model=self.model,
        )

    def _learn_identity(self, identity: HeaderIdentity) -> None:
        if identity == self._identity:
            return
        self._identity = identity
        for callback in tuple(self._identity_listeners):
            try:
                callback(identity)
            except Exception as error:
                self._rate_limited_debug(
                    "identity_listener", "Identity listener failed: %s", error
                )

    def _fail_pending(self, error: Exception) -> None:
        for pending in tuple(self._pending):
            if not pending.future.done():
                pending.future.set_exception(error)
        self._pending.clear()

    def _prune_duplicates(self, now: float) -> None:
        cutoff = now - _DUPLICATE_WINDOW
        for data, received_at in tuple(self._recent_datagrams.items()):
            if received_at < cutoff:
                del self._recent_datagrams[data]

    def _rate_limited_debug(self, key: str, message: str, *args: object) -> None:
        loop = self._loop
        if loop is None:
            return
        now = loop.time()
        if now - self._last_log_at.get(key, float("-inf")) < _INVALID_LOG_INTERVAL:
            return
        self._last_log_at[key] = now
        _LOGGER.debug(message, *args)

    def _require_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise DeviceUnavailableError("client has not been started")
        return self._loop

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise ClientClosedError("the local device client is closed")


def _set_result_all(
    waiters: list[asyncio.Future[DeviceState]], state: DeviceState
) -> None:
    for future in waiters:
        if not future.done():
            future.set_result(state)


def _set_exception_all(
    waiters: list[asyncio.Future[DeviceState]], error: Exception
) -> None:
    for future in waiters:
        if not future.done():
            future.set_exception(error)


def _merge_state(previous: DeviceState | None, incoming: DeviceState) -> DeviceState:
    """Merge a documented partial response (such as M25 backlight) safely."""

    if previous is None:
        return incoming
    values: dict[str, Any] = {}
    for state_field in fields(DeviceState):
        if state_field.name == "raw_values":
            values[state_field.name] = {**previous.raw_values, **incoming.raw_values}
            continue
        received = getattr(incoming, state_field.name)
        values[state_field.name] = (
            received if received is not None else getattr(previous, state_field.name)
        )
    return DeviceState(**values)
