FROM ubuntu:bionic

RUN apt update && apt upgrade -y
RUN apt install -y leap-archive-keyring
RUN echo "deb http://deb.leap.se/client release bionic" > /etc/apt/sources.list.d/bitmask.list
RUN apt update && apt install -y \
    bitmask \
    iptables \
    transmission-cli \
    transmission-common \
    transmission-daemon \
    patch \
    ;

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1

RUN apt install -y python3-yaml

WORKDIR /root
COPY ["bitmask-root.patch", "./"]
RUN patch -d /usr/sbin < bitmask-root.patch

COPY ["entrypoint.sh", "bitmask_init.py", "transmission_init.py", "transmission.yaml", "./"]
ENTRYPOINT ["bash", "entrypoint.sh"]
EXPOSE 9091
VOLUME ["/downloads"]
RUN mkdir -p /downloads
