#!/bin/sh
set -eu
umask 077
probe_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then
    exec python3 "$probe_root/launcher.py" "$@"
fi
echo '{"status":"failed","error":{"reason":"PYTHON3_NOT_AVAILABLE"}}'
exit 2
