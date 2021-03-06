#!/usr/bin/env bash
set -eu

function log {
    echo "$@" >&2
}

function validate_env {
  if [[ -z "${BITMASK_USER:-}" ]]; then
      echo "must define bitmask user in BITMASK_USER"
      exit 2
  elif [[ -z "${BITMASK_PASS:-}" ]]; then
      echo "must define bitmask pass in BITMASK_PASS"
      exit 2
  fi
}

function fix_dns {
  python /root/resolve_spotty_dns.py "api.calyx.net" "calyx.net" "ifconfig.me"
}

function start_bitmask {
    log "Starting bitmask"
    python /root/bitmask_init.py --check-firewall
}

function run_transmission {
  python /root/transmission_init.py \
        /root/transmission.yaml \
        "${TRANSMISSION_HOME}/settings.json"
  exec transmission-daemon --foreground
}

export TRANSMISSION_HOME="${TRANSMISSION_HOME:-$HOME/tm_config}"

if [[ "${1:-}" == "" ]]; then
    validate_env
    fix_dns
    start_bitmask
    run_transmission
else
    exec "$@"
fi
