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

function check_dns {
  python3 -c "import socket;socket.gethostbyname('apple.com')"
}

function fix_dns {
#  python3 /root/resolve_spotty_dns.py "api.calyx.net" "calyx.net" "ifconfig.me"
  log "Fixing DNS"
  if ! check_dns; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    sleep 2
  fi
  check_dns
}

function template_vpn {
  log "Templating openvpn config"
  printf '10\n1\n3\n' | python3 /root/openvpn_generator.py
  sed -ri 's|^(verify-x509-name vpn12-nyc)[\.a-z0-9]+|\1|' /root/bitmask_ovpns/*
}

function start_vpn {
    log "Starting bitmask"
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

export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

if [[ "${1:-}" == "" ]]; then
    validate_env
#    fix_dns
    template_vpn
    start_vpn
    setup_firewall
    fix_dns
    wait $openvpn_pid
else
    exec "$@"
fi
