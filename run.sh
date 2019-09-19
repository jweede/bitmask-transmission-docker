#!/usr/bin/env bash
set -eux
image_name=jweede/bitmask-transmission
image_version=0.2

image_tag="${image_name}:${image_version}"
here="$(dirname "$(realpath "$0")")"

source "${here}/dev.env"
mkdir -p "${TRANSMISSION_DOWNLOAD_DIR}"

#export DOCKER_BUILDKIT=1
#docker build --pull -t "${image_tag}" "${here}"
docker pull "${image_tag}"

exec docker run -it --rm \
    --name bitmask_transmission \
    -p 9091:9091 \
    --dns=9.9.9.9 \
    --env-file=dev.env \
    --cap-add=NET_ADMIN --device=/dev/net/tun \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --mount "type=bind,source=${TRANSMISSION_DOWNLOAD_DIR},destination=/downloads" \
    "${image_tag}" "${@}" \
    ;
