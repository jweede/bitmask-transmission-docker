#!/usr/bin/env bash
set -euo pipefail

settings_path=/config/settings.json
mkdir -p "$(dirname "${settings_path}")"

echo "Updating transmission settings in ${settings_path}..."

python3 <<PYTHON
import json
import os
import pathlib

s = pathlib.Path("${settings_path}")

try:
  settings = json.loads(s.read_text())
except:
  settings = {}

settings.update({
    "incomplete-dir-enabled": False,
    "download-dir": "/downloads",
    "watch-dir-enabled": False,
})

def set_if_exist(env_name, setting_name):
  if os.environ.get(env_name):
    settings[setting_name] = os.environ[env_name]

set_if_exist("TRANSMISSION_RPC_URL", "rpc-url")

s.write_text(json.dumps(settings, indent=4, sort_keys=True))
PYTHON

[[ -f "${settings_path}" ]]
echo "Done."