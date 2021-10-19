ARG bitmask_version=0.10.2

FROM python:2.7 as build
ARG bitmask_version

RUN set -eu \
    ; apt-get update && apt-get upgrade -y \
    ; git clone https://0xacab.org/leap/bitmask-dev.git /bitmask-dev \
    ; cd /bitmask-dev \
    ; git checkout ${bitmask_version} \
    ;
WORKDIR /bitmask-dev
COPY docker_scripts/bitmask-dev-requirements.txt ./
RUN pip install -r bitmask-dev-requirements.txt
RUN set -eu \
    ; python setup.py sdist \
    ; test -f "/bitmask-dev/dist/leap.bitmask-${bitmask_version}.tar.gz" \
    ;

FROM ubuntu:bionic as target

RUN set -eu \
    ; apt-get update && apt-get upgrade -y \
    ; apt-get install -y \
      iptables \
      transmission-cli \
      transmission-common \
      transmission-daemon \
      openvpn \
      patch \
      policykit-1 \
      python-pip \
      python-psutil \
      python-scrypt \
      python-yaml \
      python-requests \
    ; rm -rf /var/lib/apt/lists/* \
    ;

ARG bitmask_version
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1
ENV TRANSMISSION_HOME=/downloads/config
ENV PYTHONWARNINGS="ignore"

WORKDIR /root
COPY --from=build \
    "/bitmask-dev/dist/leap.bitmask-${bitmask_version}.tar.gz" \
    ./
RUN pip install "leap.bitmask-${bitmask_version}.tar.gz" 'pyrsistent<0.17.0' 'jsonschema<4.0.0'
# bitmask-root doesn't get copied for whatever reason
COPY --from=build \
    /bitmask-dev/src/leap/bitmask/vpn/helpers/linux/bitmask-root \
    /usr/sbin/
# polkit wants
COPY --from=build \
    /bitmask-dev/src/leap/bitmask/vpn/helpers/linux/se.leap.bitmask.policy \
    /usr/share/polkit-1/actions/
COPY ["patches/bitmask-root.patch", "./"]
RUN set -eu \
    ; patch -d /usr/sbin < bitmask-root.patch \
    ; rm bitmask-root.patch \
    ;
# fake out ip6tables, so it doesn't do anything
RUN set -eu \
    ; rm /sbin/ip6tables \
    ; printf "#!/bin/bash\necho \"$@\"\n" > /sbin/ip6tables \
    ; chmod +x /sbin/ip6tables \
    ;

COPY ["zerossl.crt", "/usr/local/share/ca-certificates/"]
RUN  update-ca-certificates
COPY ["docker_scripts/*", "./"]
ENTRYPOINT ["bash", "entrypoint.sh"]
EXPOSE 9091
VOLUME ["/downloads"]
