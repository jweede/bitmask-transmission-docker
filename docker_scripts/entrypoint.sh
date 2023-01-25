#!/usr/bin/env bash
set -euo pipefail

function log {
    echo "$@" >&2
}

function validate_env {
  echo ok
#  if [[ -z "${BITMASK_USER:-}" ]]; then
#      echo "must define bitmask user in BITMASK_USER"
#      exit 2
#  elif [[ -z "${BITMASK_PASS:-}" ]]; then
#      echo "must define bitmask pass in BITMASK_PASS"
#      exit 2
#  fi
}

function fix_dns {
  python3 /root/resolve_spotty_dns.py "api.calyx.net" "calyx.net" "ifconfig.me"
}

function start_vpn {
    log "Starting bitmask"
    printf '10\n1\n3\n' | python3 /root/openvpn_generator.py
    sed -ri 's|^(verify-x509-name vpn12-nyc)[\.a-z0-9]+|\1|' /root/bitmask_ovpns/*
    openvpn --config /root/bitmask_ovpns/*.ovpn &
    openvpn_pid=$!
    echo "OpenVPN launched as ${openvpn_pid}"
}

function setup_firewall {
  set -euo pipefail
  export DEBUG=true
  local gateway
  gateway="$(awk '$1 == "remote" { print $2; exit; }' /root/bitmask_ovpns/*.ovpn )"
  [[ -n "${gateway}" ]]
  python3 /root/bitmask-root firewall start "${gateway}"
}

function run_transmission {
  python3 /root/transmission_init.py \
        /root/transmission.yaml \
        "${TRANSMISSION_HOME}/settings.json"
  exec transmission-daemon --foreground
}

export TRANSMISSION_HOME="${TRANSMISSION_HOME:-$HOME/tm_config}"
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

if [[ "${1:-}" == "" ]]; then
    validate_env
#    fix_dns
    start_vpn
    setup_firewall
    run_transmission
else
    exec "$@"
fi
