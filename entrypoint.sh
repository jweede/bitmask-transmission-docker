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

log "Applying bitmask-root.patch"
patch -d /usr/sbin < bitmask-root.patch

log "Checking bitmask"
bitmaskctl user auth "${BITMASK_USER}" --pass "${BITMASK_PASS}"
echo "---"
bitmaskctl vpn get_cert
echo "---"
bitmaskctl vpn check
echo "---"
log "Starting bitmask vpn"
bitmaskctl vpn start

exec bash
