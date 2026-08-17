# Home Assistant requirements

## Identity

- repository: `jack16683/ha-352air-legacy-local`
- integration domain and package directory: `352air_legacy_local`
- display name: `352 Air Legacy Local`
- initial clean-room release: `3.0.0`
- license: GPL-3.0-or-later

No migration from the former domain is required. The user will remove the old
integration and configure this one from scratch.

## Target and compatibility

Use Home Assistant 2026.8.2 APIs and conventions. Keep compatibility with
older releases when that requires no legacy architecture or brittle version
branches. The provisional compatibility floor is 2025.12 and will be set to
the oldest version that passes validation.

Required modern patterns:

- typed `ConfigEntry[RuntimeData]` and `entry.runtime_data`;
- `Platform` enum and forwarded entry setup;
- complete unload and reconfigure support;
- setup/config-flow connection validation;
- DHCP discovery plus manual IP/MAC/model configuration;
- unique ID based on normalized MAC;
- update the configured host when the same MAC is rediscovered;
- translated entity descriptions, device classes, state classes and entity
  categories for sub-entities; the main purifier uses HA's `name = None`
  convention so it carries the device name without a redundant suffix;
- redacted diagnostics;
- strict typing and asynchronous I/O.

## Language

Simplified Chinese is the default repository documentation language. The
integration uses Home Assistant translation resolution: `zh-Hans` supplies
Chinese; English strings are the fallback for every other language.

## Device and entity shape

Every model appears as one Home Assistant device. Entity names must be unique
and supplied through translated entity descriptions, not a shared hard-coded
name.

Purifiers expose a `fan` entity with air-purifier semantics:

- percentage 0 means off;
- the fan advertises only the native `auto` preset so HomeKit's AirPurifier
  accessory does not create a separate switch for every vendor-only mode;
- complete mode choices stay on one translated HA `select` entity;
- X83-family modes: auto, sleep, turbo, manual-state reporting;
- selecting a nonzero discrete speed enters manual mode where hardware behaves
  that way;
- do not expose an X83C deep-clean preset because the tested device ignored
  its apparent command;
- avoid a separate `off` preset.

PM2.5 is a linked sensor with the proper PM2.5 device class and concentration
unit. Other proven sensors may include raw air quality, timer remaining,
cumulative processed/purified volume, temperature, humidity, CO2, and airflow.

Controls such as display light, child lock, PTC, and shutoff timer use native
light/switch/select entities only when supported by that family. Diagnostic
raw values should be disabled by default where appropriate.

Do not report filter-installed as a confident boolean from the packed filter
nibble. Do not report cloud-derived filter lifetime as a local sensor.

## Availability and command UX

- Device broadcasts update entities immediately.
- A successful validated packet marks the device available.
- Timeouts eventually mark it unavailable without log spam.
- Control entities await confirmation and raise a translated HA error on
  failure.
- Rapid percentage changes are coalesced to the newest requested value.
- Power, preset, lock, timer, and light commands are never discarded.

## Discovery safety

Discovery can consume DHCP candidates, directed read-only probes, and passive
status broadcasts. It must never provision Wi-Fi, contact cloud services,
write a device lock, or change purifier state.

Because wire type is only a family identifier, ambiguous discoveries proceed
to a model confirmation step before the entry is created.

## Diagnostics and privacy

Diagnostics redact host, MAC, auth code, device identifiers and packet bytes.
The public repository contains no captures, APKs, tokens, internal addresses,
full device MACs, certificates or Wi-Fi material. Public byte examples use
synthetic identifiers. The public 352 vendor OUI may be used as a DHCP matcher;
it identifies a manufacturer, not an individual device.

## Branding

Use an official 352 logo obtained from an official/public brand source, not a
copy of the former integration's packaged image. Put Home Assistant
custom-integration brand images under
`custom_components/352air_legacy_local/brand/`; generate any HACS root brand
directory from the same source artwork if repository validation requires it.

The code and documentation are GPL-3.0-or-later, but the official 352 logo is
explicitly excluded from that grant. Add a brand notice stating that the logo
and associated trademarks belong to their respective owner, are used only to
identify compatible devices, and do not imply affiliation or endorsement.
