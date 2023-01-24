FROM ubuntu:22.04 as target

RUN set -eu \
    ; apt-get update && apt-get upgrade -y \
    ; apt-get install -y \
      iptables \
      transmission-cli \
      transmission-common \
      transmission-daemon \
      openvpn \
      patch \
      python3 \
      python3-requests \
      python3-openssl \
      python3-psutil \
      python3-yaml \
    ; rm -rf /var/lib/apt/lists/* \
    ;

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1
ENV TRANSMISSION_HOME=/downloads/config

WORKDIR /root
# fake out ip6tables, so it doesn't do anything
RUN set -eu \
    ; rm /sbin/ip6tables \
    ; printf "#!/bin/bash\necho \"$@\"\n" > /sbin/ip6tables \
    ; chmod +x /sbin/ip6tables \
    ;
COPY ["docker_scripts/zerossl.crt", "/usr/local/share/ca-certificates/"]
RUN  update-ca-certificates
COPY ["docker_scripts/*", "./"]
ENTRYPOINT ["bash", "entrypoint.sh"]
EXPOSE 9091
VOLUME ["/downloads"]
