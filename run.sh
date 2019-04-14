#!/usr/bin/env bash
set -eux
image_name=bitmask-transmission
image_version=0.1

image_tag="${image_name}:${image_version}"
here="$(dirname "$(realpath "$0")")"

docker build -t "${image_tag}" "${here}"

exec docker run -it \
    --env-file=dev.env \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    "${image_tag}" bash
