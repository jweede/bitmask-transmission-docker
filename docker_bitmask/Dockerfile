FROM ghcr.io/astral-sh/uv:0.4 as uv
FROM docker.io/ubuntu:24.04 as target
RUN set -eu \
    ; apt-get update && apt-get upgrade -y \
    ; DEBIAN_FRONTEND=noninteractive apt-get -y install \
      openvpn \
      iptables \
      patch \
      python3 \
      python3-yaml \
      curl \
      dnsutils \
      tini \
    ; rm -rf /var/lib/apt/lists/* \
    ;
COPY --from=uv /uv /bin/uv
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1
ENV UV_TOOL_BIN_DIR=/opt/uv-bin/
RUN uv tool install riseup-vpn-configurator
ENV PATH=$UV_TOOL_BIN_DIR:$PATH
WORKDIR /root
# fake out ip6tables, so it doesn't do anything
#RUN set -eu \
#    ; rm /sbin/ip6tables \
#    ; printf "#!/bin/bash\necho \"$@\"\n" > /sbin/ip6tables \
#    ; chmod +x /sbin/ip6tables \
#    ;
COPY ./*.sh ./*.patch /root/
RUN chmod +x /root/*.sh
RUN patch -d /root/.local/share/uv/tools/riseup-vpn-configurator/lib/python3.12/site-packages/riseup_vpn_configurator -u </root/fix_requests.patch
#RUN cp zerossl.crt /usr/local/share/ca-certificates/
#RUN  update-ca-certificates
ENTRYPOINT ["/usr/bin/tini", "--", "/root/entrypoint.sh"]
#EXPOSE 9091
#VOLUME ["/downloads"]
