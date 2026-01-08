#!/usr/bin/env bash
set -euo pipefail

tee /etc/riseup-vpn.yaml <<YAML
---
# /etc/riseup-vpn.yaml

#server: vpn12-nyc.riseup.net
server: vpn18-mtl.riseup.net
protocol: udp
port: 53

# excluded_routes: list services that should not be routed over VPN
# can be an ipaddress, network or hostname
# your local subnet is excluded by default
excluded_routes:
  - 8.8.8.8
  - 8.8.4.4
  - 1.1.1.1

# os user/group
user: root
group: root
YAML

mkdir -p /etc/openvpn/client

riseup-vpn-configurator --update
riseup-vpn-configurator -g