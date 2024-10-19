#!/usr/bin/env bash
set -euo pipefail

function log {
  echo "$@" >&2
}

settings_path=/config/settings.json
mkdir -p "$(dirname "${settings_path}")"

log "Updating transmission settings in ${settings_path}..."

python3 /transmission_settings.py "${settings_path}"

[[ -f "${settings_path}" ]]
log "Done."