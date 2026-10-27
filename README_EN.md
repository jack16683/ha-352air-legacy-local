# 352 Air Legacy Local

[简体中文](README.md)

A local Home Assistant integration for already-networked 352 devices. Legacy
Air devices use UDP 11530 for state and control. Newer Life devices can be
discovered through read-only CoAP and added with local connection status.
No 352 account or cloud connection is required.

> This is an independent community integration. It is not affiliated with or
> endorsed by 352.

## Why this project exists

This is not a vague old-app compatibility problem. The APK hard-codes account
login, token validation, and the device list to `https://352.yunext.com`; its
device-cloud bootstrap also uses port `11591` on the same host. On 2026-08-18,
both Cloudflare and Google public DNS-over-HTTPS resolvers returned `NXDOMAIN`
for that hostname. The parent domain still exists, but the legacy service host
record has been removed. The app therefore cannot locate its server before it
can even validate a password; this is not a purifier failure or a wrong-password
error.

Devices such as the X83C still broadcast state and accept independent local
control over UDP port 11530. This project documented that LAN protocol through
static APK analysis, sanitized packet observations, and X83C hardware
validation, then created a new implementation for the Home Assistant 2026.8
API.

Thanks to [yymonday/ha-352-airpurifier](https://github.com/yymonday/ha-352-airpurifier)
for preserving early X83/X50 community experience. Version 3 is a new
GPL-3.0-or-later implementation and does not inherit that repository's source
or Git history. The [research index](docs/README.md) links the
[protocol analysis](docs/protocol-analysis.md), the complete Chinese-language
[APK static-analysis report](docs/apk-static-analysis.md), and the sanitized
[X83C capture and hardware-validation report](docs/x83c-capture-validation.md).

## Legacy Air support confidence

| Model | State | Control | Evidence |
|---|---|---|---|
| X83C | Supported | Supported | Hardware-verified; auth is learned from the device |
| X83 | Supported | Supported | Reported working by the original project; same A5A0 family |
| X50 | Supported | Experimental | Listed as hardware-tested upstream; firmware control differs |
| X83C Plus | Experimental | Experimental | APK confirms the X83 family; no project hardware |
| X50S / X60 / X70 | Experimental | Experimental | APK confirms the X50 family; no project hardware |
| G30 / G45 | Experimental | Experimental | APK confirms framing, CRC, and command tables |
| M25 | Experimental | Backlight only | Air monitor, not an air-purifier control surface |

APK confirmation proves that the old app contained a builder/parser; it does
not prove that every firmware accepts a command. Retail models such as Plus
and G30/G45 may use different connection systems; actual replies determine
which path can be used.

## Life devices: local discovery and setup

Both automatic and manual setup try legacy UDP, CoAP device-info, and ALCS
discovery. Enabled HA IPv4 adapters are respected, and one failing mechanism
does not prevent the others from finding a device.

The built-in catalog recognizes 35 product keys across air purifiers, water
purifiers, and humidifiers, including X83C Plus, X86/X86C, X86 Pro, X63C/X66C,
X63C Pet, X88/X88C, X89C, Y100/Y100C, Y109/Y109C, Z70/Z90/Z91/Z120/Z122,
Q80, G30/G45, S100/K10/S130/S106/B420/B425HC, Dr03/Dr10, and
Skin/H80/H100/H150/H300/H301/H400/H500/H520 families. Shared product keys
retain combined model labels.

**Catalog recognition is not hardware or control verification.** A valid
local response is required. Life setup explains the limited functionality
before creating only a diagnostic **Local connection** entity. It does not
create power, fan-speed, humidity, or air-quality entities. Read-only
reachability probes do not establish control authorization.

This scope includes no cloud login, device binding, Bluetooth provisioning,
SoftAP network switching, firmware updates, or cloud interception. Devices
must already be on the LAN; entering a model alone cannot add a silent device.

## Features

- LAN discovery plus manual IP/MAC setup.
- Learns company, protocol family, and authentication fields from replies.
- One main fan entity: 0% powers off, with a speed slider and auto, manual,
  sleep, turbo, and model-supported experimental deep-clean modes. No separate
  mode entity is created.
- PM2.5, air quality, filter airflow profile, current-run processed air,
  lifetime purified air, current airflow, remaining timer, and proven model
  sensors. Discrete-speed airflow is calculated from the APK profile curve;
  G30/G45 uses the reported airflow.
- Child lock, display, shutoff timer, and G30/G45 PTC controls.
- Push updates from broadcasts with read-only refresh when broadcasts go stale.
- Simplified Chinese translation; English fallback for every other HA language.
- No cloud communication.

On X83C, setting a speed enters manual mode. The verified unit ignored mode
command values 4 and 5, so this project does not expose an unverified
“deep-clean” preset as if it worked. Turbo is a separate persistent mode.

## Install with HACS

1. Open **HACS → Integrations**.
2. Open the top-right menu and select **Custom repositories**.
3. Add:

   ```text
   https://github.com/jack16683/ha-352air-legacy-local
   ```

4. Select the **Integration** category and download
   **352 Air Legacy Local**.
5. Restart Home Assistant.
6. Open **Settings → Devices & services → Add integration** and search for
   **352 Air Legacy Local**.

Discovery lists devices with valid replies. Legacy Air devices require model
confirmation; Life devices require confirmation of discovery-only setup.
Manual setup needs the current IP address; MAC is optional and Auto can
identify the product. Supplying legacy auth/company values still requires a
MAC. Discovery never provisions Wi-Fi or locks a device.

Only legacy devices with supported recurring schedules offer the separate
option to clear all four stored schedule slots. It is off by default and
requires two successful empty reads after a write. Reconfiguration verifies
that the responding identity belongs to the same device.

## Check schedules left by the old app

Recurring power schedules may be stored in the purifier MCU and can continue
running after the old account stops working. The included standalone tool has
been exercised on Windows, Linux, and macOS:

```bash
cd tools
python3 352air_schedule_manager.py
```

Initial setup and reconfiguration can now clear all four slots. The standalone
tool remains useful for inspecting exact slot contents, setting device-local
schedules, or managing schedules without HA. Remove obsolete device schedules,
then manage power times with Home Assistant automations to avoid two conflicting
schedules. See the
[schedule-manager guide](docs/schedule-manager.md).

## HomeKit

Home Assistant's `fan` domain has no native air-purifier device class. Tell the
HomeKit Bridge to represent the main fan as `air_purifier` and link PM2.5:

```yaml
homekit:
  - filter:
      include_entities:
        - fan.352_air_x83c
    entity_config:
      fan.352_air_x83c:
        type: air_purifier
        linked_pm25_sensor: sensor.352_air_x83c_pm2_5
```

Replace the example entity IDs with the IDs from your HA instance. Apple Home
then shows one purifier accessory with power, auto/manual, a speed slider, and
linked PM2.5; moving the slider to 0 powers off.

The integration correctly publishes every mode through the main fan's
`preset_modes`. Home Assistant's built-in HomeKit Bridge converts each non-auto
preset into a linked switch because HomeKit has no native sleep, turbo, or deep-
clean target states. To avoid those buttons, create a preset-free Template Fan
proxy, bridge only the proxy to HomeKit, and keep the original fan in HA for the
complete mode control. Do not bridge both entities.

## Privacy and safety

- No 352 cloud connection or telemetry upload.
- No APK, raw capture file, certificate, full device MAC, private IP, HA token, or Wi-Fi
  data; discovery uses only 352's public vendor OUI prefix.
- Diagnostics redact hosts, MACs, auth values, and raw packets.
- Discovery is read-only and never reproduces the old app's lock operation.
  Schedule cleanup is a separate write step that is off until explicitly chosen.

Use this project only with devices you own or are authorized to manage.

## License

Code and original documentation are licensed under
[GPL-3.0-or-later](LICENSE). The official 352 logo and associated trademarks
are excluded from that license and are used only to identify compatible
devices; see [NOTICE](NOTICE).
