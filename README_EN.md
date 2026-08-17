# 352 Air Legacy Local

[简体中文](README.md)

A fully local Home Assistant integration for already-networked legacy 352 air
devices. It reads state and sends controls over LAN UDP port 11530, without a
352 account or the retired cloud service.

> This is an independent community integration. It is not affiliated with or
> endorsed by 352.

## Why this project exists

The 352Air app used around 2019 can no longer be relied on for account login,
while devices such as the X83C still broadcast state and accept local control.
This project documented the LAN protocol through static APK analysis,
sanitized packet observations, and X83C hardware validation, then created a
new implementation for the Home Assistant 2026.8 API.

Thanks to [yymonday/ha-352-airpurifier](https://github.com/yymonday/ha-352-airpurifier)
for preserving early X83/X50 community experience. Version 3 is a new
GPL-3.0-or-later implementation and does not inherit that repository's source
or Git history. See the [protocol analysis](docs/protocol-analysis.md) for the
implementation evidence and remaining uncertainties. The full reverse-
engineering notes are also published in the Chinese-language
[APK static-analysis report](docs/apk-static-analysis.md).

## Support confidence

| Model | State | Control | Evidence |
|---|---|---|---|
| X83C | Supported | Supported | Verified on a 2019 unit; auth is learned from the device |
| X83 | Supported | Supported | Reported working by the original project; same A5A0 family |
| X50 | Supported | Experimental | Listed as hardware-tested upstream; firmware control differs |
| X83C Plus | Experimental | Experimental | APK confirms the X83 family; no project hardware |
| X50S / X60 / X70 | Experimental | Experimental | APK confirms the X50 family; no project hardware |
| G30 / G45 | Experimental | Experimental | APK confirms framing, CRC, and command tables |
| M25 | Experimental | Backlight only | Air monitor, not an air-purifier control surface |

APK confirmation proves that the old app contained a builder/parser; it does
not prove that every firmware accepts a command.

## Features

- LAN discovery plus manual IP/MAC setup.
- Learns company, protocol family, and authentication fields from replies.
- Main fan entity: 0% powers off; nonzero speed, auto/manual, and a speed slider.
- HA mode selector for sleep, turbo, and model-supported experimental deep clean.
- PM2.5, remaining timer, cumulative air volume, and proven model sensors.
- Model-supported child lock, display, PTC, and shutoff timer controls.
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

Discovery identifies a protocol family first and asks for the exact model when
the LAN protocol cannot distinguish retail variants. Use manual setup with the
device IP, MAC, and model if discovery is unavailable. Setup never provisions
Wi-Fi, locks the device, or changes purifier state.

## Check schedules left by the old app

Recurring power schedules may be stored in the purifier MCU and can continue
running after the old account stops working. The included standalone tool has
been exercised on Windows, Linux, and macOS:

```bash
cd tools
python3 352air_schedule_manager.py
```

It queries all four slots immediately after device selection. Remove obsolete
device schedules, then manage power times with Home Assistant automations to
avoid two conflicting schedules. See the
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
linked PM2.5; moving the slider to 0 powers off. HomeKit's purifier service has
no native sleep or turbo target states, so the full mode list remains in HA's
**Operating mode** entity instead of becoming extra HomeKit buttons.

## Privacy and safety

- No 352 cloud connection or telemetry upload.
- No APK, capture, certificate, full device MAC, private IP, HA token, or Wi-Fi
  data; discovery uses only 352's public vendor OUI prefix.
- Diagnostics redact hosts, MACs, auth values, and raw packets.
- Discovery is read-only and never reproduces the old app's lock operation.

Use this project only with devices you own or are authorized to manage.

## License

Code and original documentation are licensed under
[GPL-3.0-or-later](LICENSE). The official 352 logo and associated trademarks
are excluded from that license and are used only to identify compatible
devices; see [NOTICE](NOTICE).
