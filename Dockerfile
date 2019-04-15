FROM ubuntu:bionic

RUN apt update && apt upgrade -y
RUN apt install -y leap-archive-keyring
RUN echo "deb http://deb.leap.se/client release bionic" > /etc/apt/sources.list.d/bitmask.list
RUN apt update && apt install -y bitmask iptables
RUN apt install -y vim patch

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV LEAP_DOCKERIZED=1

WORKDIR /root
COPY ["bitmask-root.patch", "./"]
RUN patch -d /usr/sbin < bitmask-root.patch

COPY ["entrypoint.sh", "bitmask_init.py", "./"]
ENTRYPOINT ["bash", "entrypoint.sh"]
