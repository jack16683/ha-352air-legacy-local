# 352 Air Legacy Local: factual protocol specification

## Scope and safety

The integration controls already-networked legacy 352 air devices over local
UDP port 11530. It never contacts the retired 352 cloud service and never
performs Wi-Fi provisioning.

Discovery and setup must be read-only. In particular, never reproduce the old
mobile application's post-discovery lock operation (`0x24`). Every public
example must use synthetic addresses and identifiers.

Evidence labels used by the product:

- `verified`: exercised on physical hardware;
- `apk`: present in the old Android application's builders/parsers;
- `experimental`: structurally supported but not verified on that model;
- `unknown`: retain the raw value and do not invent a label.

## Product and protocol families

| Model | point type | wire type | inner family | confidence |
|---|---:|---:|---|---|
| M25 | 1 | 1 | FA/E5 | APK; detector, not purifier |
| X83 | 2 | 2 | A5A0 | historically reported working |
| G30 | 3 | 4 | F072 | APK, experimental |
| X83C | 4 | 2 | A5A0 | verified on 2019 hardware |
| X50 | 5 | 3 | F072 | status historically reported; control experimental |
| X50S | 6 | 3 | F072 | APK, experimental |
| X83C Plus | 7 | 2 | A5A0 | APK family match, experimental |
| X60 | 8 | 3 | F072 | APK, experimental |
| X70 | 9 | 3 | F072 | APK, experimental |
| G45 | 10 | 4 | F072 | APK, experimental |

Wire type identifies a family, not necessarily the retail model. The only
known best-effort discriminator is an MCU version containing `G45`.

## Outer UDP envelope

All offsets are zero-based.

```text
offset  size  field
0       1     0xA1
1       1     0x04 for outgoing read/control/discovery requests
2       6     target MAC
8       1     payload length + 7
9       1     0x00
10      2     outer sequence, big-endian
12      1     company code
13      1     wire type
14      2     authentication code, big-endian
16      N     routed payload
```

The full datagram size is `16 + len(payload)`. Sequence values are unsigned
16-bit values and wrap naturally. A configured device is keyed by normalized
MAC, not by its changing IPv4 address.

Verified X83C state broadcasts/responses may begin with `A1 06`; `0x06` is
accepted on receive but is not used as the normal outgoing request flag.

Every valid response can refresh MAC, company, wire type, and authentication
code. Normal queries and controls must use learned company/type/auth values;
they must not use values copied from another model or device.

### Read-only directed discovery

Given a candidate IPv4 address and MAC, send:

```text
A1 04 <MAC:6> 08 00 <SEQ:2> F1 <WIRE_TYPE> CB 76 23
```

Probe wire types 1 through 4 when the family is unknown. A response is at
least 27 bytes and its routed content contains:

```text
23 <IPv4:4> <MAC:6>
```

The response outer header supplies the device's company, wire type and auth.
Some devices reply twice. Duplicate datagrams are normal and must not produce
duplicate devices or callbacks.

The integration may also accept unsolicited UDP 11530 status broadcasts.
DHCP discovery can provide candidate IP/MAC pairs, but a manual IP/MAC flow
must remain available. Exact model confirmation is required when the family
is ambiguous.

## A5A0 family: X83, X83C, X83C Plus

The route byte is `01`.

Fixed state query:

```text
01 A5 A0 11 11 00 00
```

Control payload:

```text
01 A5 A0 <COMMAND> <VALUE> 00 <CHECKSUM>
CHECKSUM = sum(A5, A0, COMMAND, VALUE, 00) & 0xFF
```

Commands confirmed by Android static analysis:

| Operation | command | values |
|---|---:|---|
| operating mode | 0x51 | 1 auto, 2 sleep, 3 turbo, 5 app-labelled deep clean |
| discrete speed | 0x52 | 1..6 |
| PTC | 0x53 | 0, 1, 2 |
| shutoff timer | 0x54 | 0, 1, 2, 3, 5, 8 hours |
| child lock | 0x55 | 0x00 off, 0x11 on |
| display light | 0x56 | 0x00 on, 0x11 off |
| filter operation | 0x57 | 1, 2, 3; semantics require model evidence |
| power | 0x5E | 0x35 on, 0x11 off |

X83C hardware observations override generic assumptions:

- status modes are 1 auto, 2 sleep, 3 turbo, 4 manual;
- a speed command enters manual mode;
- mode commands with values 4 and 5 were ignored by the tested X83C;
- turbo is persistent and must not be called deep clean;
- the tested X83C advertised auth `0x0403`; this is evidence that auth must be
  learned, not a constant to ship.

For a normal 49-byte X83C UDP state datagram, absolute offsets are:

| offset | meaning |
|---:|---|
| 19 | high nibble filter type; low nibble mode |
| 20 | speed, 1..6 |
| 21 | selected timer hours, 0/1/2/3/5/8 |
| 22 | raw air-quality class, observed/parsed 1..3 |
| 23 | child lock, 0x00 off / 0x11 on |
| 24 | display, 0x00 on / 0x11 off |
| 25 | power, 0x00 on / 0x11 off |
| 26..27 | remaining timer minutes, big-endian |
| 28..29 | PM2.5 integer, big-endian |
| 37..39 | cumulative processed air: decimal exponent + big-endian base |
| 40..42 | cumulative purified air: decimal exponent + big-endian base |

For the APK-defined exponent range 0 through 3, the cumulative encoding is
`base * 10**exponent`. Treat it as cumulative
volume in cubic metres and preserve the raw exponent/base in diagnostics.
Do not reinterpret the value as a reset-on-power-cycle counter.

The air-quality class 1/2/3 has no proven Chinese or English adjectives. It
must remain a raw numeric diagnostic until model evidence exists.

The filter high nibble is a type/position indicator, not proof that an
official, unexpired filter is installed. Do not expose it as a confident
`installed` condition. Filter lifetime is cloud/application metadata unless a
separate device field is proven.

## F072 family

X50/X50S/X60/X70 use wire type 3 and inner type 3. G30/G45 use wire type 4
and inner type 4. The route byte is `01`.

Single-value request body, 15 bytes:

```text
F0 72 00 0D <INNER_TYPE> 04 02 <INNER_SEQ:2> 03 <CMD> <VALUE> 00 <CRC:2>
```

CRC covers bytes 2 through 12 inclusive and uses CRC-16/GENIBUS:

- polynomial 0x1021;
- initial value 0xFFFF;
- no reflection;
- xor-out 0xFFFF;
- big-endian result.

The state query uses command/value `0x11/0x11`.

### X50-family controls

| operation | command | values |
|---|---:|---|
| mode | 0x51 | 1 auto, 2 sleep, 3 turbo, 5 app-labelled deep clean |
| speed/room preset | 0x52 | 1..5; 0 is a stop/sentinel in the UI table |
| PTC | 0x53 | 0, 1, 2 |
| shutoff timer | 0x54 | 0/1/2/3/5/8 hours |
| child lock | 0x55 | 0x00 on, 0x11 off |
| display | 0x56 | 0x00 on, 0x11 off |
| power | 0x5E | 0x00 on, 0x11 off |

These controls are experimental. There is external historical evidence of an
X50 reporting state while rejecting older local control implementations.

After F072 length and CRC validation, the X50-family state data area contains:

| data offset | meaning |
|---:|---|
| 3 | packed filter/mode |
| 4 | discrete speed; parser accepts 1..6 although the control table uses 1..5 |
| 5 | selected timer |
| 6 | raw air quality |
| 7 | child lock |
| 8 | display |
| 9 | power |
| 10..11 | remaining minutes |
| 12..13 | PM2.5 |
| 19..20 | total online-time raw counter |
| 21 | processed-air decimal exponent |
| 22..23 | processed-air base, big-endian |
| 24 | purified-air decimal exponent |
| 25..26 | purified-air base, big-endian |
| 29 | linkage raw value |

The boolean state convention is `0x00` true/on and `0x11` false/off for lock,
display, and power. Do not expose a PTC state for X50 unless another proven
field is found; a command builder alone is not a state field.

### G30/G45 controls

The single-value operations use the same F072 layout with inner type 4.

| operation | command | values |
|---|---:|---|
| mode | 0x51 | UI proves 1 auto and 5 deep clean; 2..4 remain unproven controls |
| PTC | 0x53 | 0, 1, 2 |
| shutoff timer | 0x54 | 0/1/2/3/5/8 hours |
| child lock | 0x55 | 0x00 on, 0x11 off |
| display | 0x56 | 0x00 on, 0x11 off |
| power | 0x5E | 0x00 on, 0x11 off |

Continuous airflow is a two-byte value:

```text
F0 72 00 0D 04 04 02 <INNER_SEQ:2> 03 58 <FLOW:2> <CRC:2>
```

- G30: 40..300 m3/h, step 5.
- G45: 40..450 m3/h, step 5.
- Home Assistant 0% means power off.
- For nonzero percent, linearly map 1..100% to the supported flow range and
  round to step 5. This percentage is an integration convention, not an APK
  field.

After CRC validation, the G30-family status data area contains:

| data offset | meaning |
|---:|---|
| 3 | packed filter/mode |
| 5 | selected timer |
| 6 | raw air quality |
| 7 | child lock |
| 8 | display |
| 9 | power |
| 10..11 | remaining minutes |
| 12..13 | PM2.5 |
| 14 | temperature |
| 15 | humidity |
| 16..17 | CO2 |
| 18 | PTC |
| 19..20 | total online-time raw counter |
| 21 | processed-air decimal exponent |
| 22..23 | processed-air base, big-endian |
| 24 | purified-air decimal exponent |
| 25..26 | purified-air base, big-endian |
| 27..28 | airflow m3/h |

Do not parse any field until the declared length and CRC have passed.

## M25 detector family

Wire type 1 uses route byte `03`. M25 is not a purifier and must not expose
power, fan, mode, child lock, PTC, or timer entities without new evidence.

| operation | routed inner frame |
|---|---|
| read sensor state | `03 FA A0 11 11 00 00` |
| read backlight | `03 FA A4 02 01 A1` |
| five-minute backlight | `03 FA A3 03 01 00 A1` |
| always-on backlight | `03 FA A3 03 01 01 A2` |

M25 responses include `03 E5 A1/A2` state forms and `03 E5 A3/A4` backlight
forms. Expose only fields that can be bounds-checked and proven.

## Runtime behavior

- Share one long-lived UDP 11530 endpoint across discovery and every configured
  device, then dispatch by MAC. Receive both replies and broadcasts.
- Permit a less-compatible ephemeral fallback if another process owns 11530.
  The verified X83C replies to fixed port 11530, so the fixed bind remains the
  reliable path and the standalone schedule tool should not run concurrently.
- De-duplicate identical replies.
- Allocate separate outer and F072 inner sequence counters.
- Match responses using device MAC, family, response kind, and sequence where
  the response preserves it.
- Serialize writes per device. Coalesce superseded percentage writes from UI
  sliders, but never drop power or preset commands.
- After a control command, wait for a validated confirming state. Do not leave
  an optimistic state stuck after timeout.
- Periodically issue read-only queries only when broadcasts have gone stale.
- Invalid packets are ignored with rate-limited debug logging.
- No socket/network blocking work runs in the Home Assistant event loop.

## Local schedule utility

The existing cross-platform schedule manager is a separately authored,
field-tested tool. It is outside the rewrite scope. It may be copied unchanged
after the primary reviewer confirms its provenance and licensing boundary.
