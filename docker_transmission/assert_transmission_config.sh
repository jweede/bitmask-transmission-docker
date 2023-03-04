#!/usr/bin/env bash
set -euo pipefail

settings_path=/config/settings.json
mkdir -p "$(dirname "${settings_path}")"

if [[ ! -f "${settings_path}" ]]; then
  echo '{}' >"${settings_path}"
fi

echo "Updating transmission settings..."

python3 <<PYTHON
import pathlib
import json

s = pathlib.Path("${settings_path}")

settings = json.loads(s.read_text())
settings.update({
    "incomplete-dir-enabled": False,
    "download-dir": "/downloads",
    "watch-dir-enabled": False,
})

s.write_text(json.dumps(settings, indent=4, sort_keys=True))
PYTHON

[[ -f "${settings_path}" ]]
echo "Done."