# API contract between protocol and Home Assistant layers

The parallel implementations must target this contract. The primary reviewer
may refine names during integration, but must preserve the separation of pure
protocol code from Home Assistant.

## Pure models

`models.py` defines new typed values with no Home Assistant imports:

- `DeviceModel`: M25, X83, G30, X83C, X50, X50S, X83C_PLUS, X60, X70, G45.
- `ProtocolFamily`: M25, A5A0, F072_X50, F072_G30.
- `HeaderIdentity`: MAC bytes, company, wire type, auth.
- immutable `DeviceState` containing only optional, proven fields plus raw
  diagnostic values.
- immutable `DecodedPacket`: identity, sequence, packet kind, optional state,
  source endpoint, raw metadata required for diagnostics.
- enums for power/mode only where semantics are proven. Unknown integer values
  remain integers and never raise during state parsing.

## Protocol facade

`protocols` exposes a family-selected codec with pure methods conceptually
equivalent to:

```python
class DeviceCodec(Protocol):
    def encode_query(self, context: CommandContext) -> bytes: ...
    def encode_command(self, context: CommandContext, command: Command) -> bytes: ...
    def decode(self, datagram: bytes, source: tuple[str, int]) -> DecodedPacket | None: ...
```

The concrete naming may differ, but encoders must be deterministic when given
fixed sequence numbers. Parsing malformed or unrelated traffic returns no
state and never leaks `IndexError`/`struct.error`.

## Transport facade

`transport.py` supplies an asyncio-native, Home-Assistant-independent client:

```python
class LocalDeviceClient:
    state: DeviceState | None
    identity: HeaderIdentity

    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def refresh(self) -> DeviceState: ...
    async def command(self, command: Command) -> DeviceState: ...
    def add_listener(self, callback: Callable[[DeviceState], None]) -> Callable[[], None]: ...
```

Required behaviors:

- a control call does not succeed until a confirming validated state arrives;
- timeout and unavailable errors use dedicated exception classes;
- callbacks run in the event loop and never while internal locks are held;
- closing resolves pending requests with a closed-client exception;
- no task or socket survives unload;
- learned identity changes are observable by the HA runtime for persistence.

## HA runtime facade

The HA layer owns a typed runtime object stored in `ConfigEntry.runtime_data`.
It creates the client, translates client state into entities, persists learned
header fields, and exposes one shared device description.

Entity modules must not construct or parse packets. Config flow discovery may
use a small read-only discovery facade from `discovery.py`.

## Ownership during parallel work

- protocol agent owns `models.py`, `transport.py`, and `protocols/`;
- HA agent owns `__init__.py`, `runtime.py`, `discovery.py`, `config_flow.py`,
  `diagnostics.py`, `entity.py`, and entity platforms;
- validation agent writes only outside the public repository;
- primary reviewer owns metadata, translations, docs, branding, packaging,
  integration fixes, Git, deployment, and publication.

