#!/usr/bin/env bash
set -euo pipefail

here="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

function log {
    echo "$@" >&2
}

export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

if [[ "${1:-}" == "" ]]; then
    log "Templating VPN"
    "${here}"/template_vpn.sh
    log "Starting bitmask"
    exec openvpn --config /etc/openvpn/client/riseup.conf
else
    exec "$@"
fi
