#!/usr/bin/env bash
set -euo pipefail

function log {
    echo "$@" >&2
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
  cat - >/etc/riseup-vpn.yaml <<YAML
---
# /etc/riseup-vpn.yaml

server: vpn12-nyc.riseup.net
protocol: udp
port: 53

# excluded_routes: list servcies that should not be routed over VPN
# can be an ipaddress, network or hostname
# your local subnet is excluded by default
excluded_routes:
  - 8.8.8.8

# os user/group
user: root
group: root
YAML

  mkdir -p /etc/openvpn/client
  log "Templating openvpn config"
  riseup-vpn-configurator --update
  riseup-vpn-configurator -g
}

function start_vpn {
    log "Starting bitmask"
    openvpn --config /etc/openvpn/client/riseup.conf
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
#    fix_dns
    template_vpn
    exec openvpn --config /etc/openvpn/client/riseup.conf
#    start_vpn
#    setup_firewall
#    fix_dns
    wait $openvpn_pid
else
    exec "$@"
fi
