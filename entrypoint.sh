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

log "Starting bitmask"
python3 /root/bitmask_init.py -d

exec bash
