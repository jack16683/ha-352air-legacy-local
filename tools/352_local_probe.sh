#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Keep this launcher beside 352_local_probe.py. Run: sh 352_local_probe.sh PLUS_IP [X83C_IP]
# No installation, sudo, container restart, or network/configuration changes.
set -u

probe_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd) || exit 1
probe_source=$probe_dir/352_local_probe.py
if [ ! -r "$probe_source" ]; then
    printf '%s\n' '{"status":"launcher_error","reason":"352_local_probe.py must be beside this launcher"}'
    exit 1
fi

# This small check is also parseable by Python 2 and older Python 3.
probe_check='import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'
for probe_python in python3 python3.15 python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 /usr/bin/python3 /bin/python3 /usr/local/bin/python3 /var/packages/Python3/target/usr/local/bin/python3 /var/packages/Python3.9/target/usr/local/bin/python3.9 python; do
    if command -v "$probe_python" >/dev/null 2>&1 &&
       "$probe_python" -c "$probe_check" >/dev/null 2>&1 &&
       "$probe_python" "$probe_source" --check-runtime >/dev/null 2>&1; then
        printf '%s\n' 'Runtime check passed: NAS/host Python. Starting diagnostics.' >&2
        PROBE_RUNTIME=host_python
        export PROBE_RUNTIME
        exec "$probe_python" "$probe_source" "$@"
    fi
done

printf '%s\n' 'No usable host Python 3.8+. Checking existing Home Assistant containers.' >&2
probe_docker=
for probe_candidate in docker /usr/local/bin/docker /var/packages/ContainerManager/target/usr/bin/docker /var/packages/Docker/target/usr/bin/docker; do
    if command -v "$probe_candidate" >/dev/null 2>&1; then
        probe_docker=$probe_candidate
        break
    fi
done
probe_matches=0
probe_container=
probe_docker_state=unavailable
if [ -n "$probe_docker" ]; then
    if probe_containers=$("$probe_docker" ps -q 2>/dev/null); then
        probe_docker_state=available
        for probe_id in $probe_containers; do
            # docker ps returns hex IDs. Do not pass arbitrary external text as flags.
            case "$probe_id" in ''|*[!0-9a-f]*) continue ;; esac
            probe_image=$("$probe_docker" inspect --format '{{.Config.Image}}' "$probe_id" 2>/dev/null) || continue
            case "$probe_image" in
                ghcr.io/home-assistant/home-assistant:*|ghcr.io/home-assistant/home-assistant@*|homeassistant/home-assistant:*|homeassistant/home-assistant@*) ;;
                *) continue ;;
            esac
            probe_network=$("$probe_docker" inspect --format '{{.HostConfig.NetworkMode}}' "$probe_id" 2>/dev/null) || continue
            [ "$probe_network" = host ] || continue
            "$probe_docker" exec "$probe_id" python3 -c "$probe_check" >/dev/null 2>&1 || continue
            "$probe_docker" exec -i "$probe_id" python3 - --check-runtime < "$probe_source" >/dev/null 2>&1 || continue
            probe_matches=$((probe_matches + 1))
            probe_container=$probe_id
        done
    else
        probe_docker_state=inaccessible
    fi
fi
if [ "$probe_matches" -eq 1 ]; then
    printf '%s\n' 'Runtime check passed: existing HA container, verified host network.' \
        'Host packet capture may be unavailable in this fallback; UDP tests will still run.' >&2
    exec "$probe_docker" exec -i --env PROBE_RUNTIME=host_ha_container \
        "$probe_container" python3 - "$@" < "$probe_source"
fi
printf '{"status":"runtime_unavailable","host_python":"missing_old_or_incomplete","docker":"%s","eligible_host_ha_containers":%s,"next_step":"Share this report. No software or network changes were made."}\n' \
    "$probe_docker_state" "$probe_matches"
exit 1
