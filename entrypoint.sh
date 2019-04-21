#!/usr/bin/env bash
set -eu

function log () {
    echo "$@" >&2
}

if [[ -z "${BITMASK_USER:-}" ]]; then
    echo "must define bitmask user in BITMASK_USER"
    exit 2
elif [[ -z "${BITMASK_PASS:-}" ]]; then
    echo "must define bitmask pass in BITMASK_PASS"
    exit 2
fi
export TRANSMISSION_HOME="${TRANSMISSION_HOME:-$HOME/tm_config}"

function start_bitmask () {
    log "Starting bitmask"
    python /root/bitmask_init.py -d
}

if [[ "${1:-}" == "" ]]; then
    start_bitmask
    python /root/transmission_init.py \
        /root/transmission.yaml \
        "${TRANSMISSION_HOME}/settings.json"
    exec transmission-daemon --foreground
else
    exec "$@"
fi
