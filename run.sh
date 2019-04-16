#!/usr/bin/env bash
set -eux
image_name=bitmask-transmission
image_version=0.1

image_tag="${image_name}:${image_version}"
here="$(dirname "$(realpath "$0")")"

source "${here}/dev.env"
mkdir -p "${TRANSMISSION_DOWNLOAD_DIR}"

docker build -t "${image_tag}" "${here}"

exec docker run -it --rm \
    --name bitmask_transmission \
    -p 9091:9091 \
    --env-file=dev.env \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --mount "type=bind,source=${TRANSMISSION_DOWNLOAD_DIR},destination=/downloads" \
    "${image_tag}" "${@}" \
    ;
