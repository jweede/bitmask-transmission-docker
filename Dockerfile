FROM ubuntu:22.04 as target
RUN set -eu \
    ; apt-get update && apt-get upgrade -y \
    ; apt-get install -y \
      openvpn \
      iptables \
      transmission-cli \
      transmission-common \
      transmission-daemon \
      patch \
      python3 \
      python3-jinja2 \
      python3-requests \
      python3-openssl \
      python3-psutil \
      python3-yaml \
      curl \
      dnsutils \
      tini \
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
COPY ./docker_scripts /root/
RUN chmod +x /root/*.sh /root/*.py
RUN cp zerossl.crt /usr/local/share/ca-certificates/
RUN  update-ca-certificates
ENTRYPOINT ["/usr/bin/tini", "--", "/root/entrypoint.sh"]
EXPOSE 9091
VOLUME ["/downloads"]
