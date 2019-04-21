FROM ubuntu:bionic

RUN set -eu \
    ; apt update && apt upgrade -y \
    ; apt install -y leap-archive-keyring \
    ; echo "deb http://deb.leap.se/client release bionic" > /etc/apt/sources.list.d/bitmask.list \
    ; apt update && apt install -y \
      bitmask \
      iptables \
      transmission-cli \
      transmission-common \
      transmission-daemon \
      patch \
      python-yaml \
      python-requests \
    ; rm -rf /var/lib/apt/lists/*

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1
ENV TRANSMISSION_HOME=/downloads/config

WORKDIR /root
COPY ["bitmask-root.patch", "./"]
RUN patch -d /usr/sbin < bitmask-root.patch

COPY ["entrypoint.sh", "bitmask_init.py", "transmission_init.py", "transmission.yaml", "./"]
ENTRYPOINT ["bash", "entrypoint.sh"]
EXPOSE 9091
VOLUME ["/downloads"]
