FROM ubuntu:22.04
RUN set -eu \
    ; apt-get update \
    ; apt-get upgrade -y \
    ; apt-get install -y \
      build-essential automake autoconf libtool pkg-config intltool libcurl4-openssl-dev \
      libglib2.0-dev libevent-dev libminiupnpc-dev libgtk-3-dev libappindicator3-dev git cmake \
      libssl-dev python3 \
    ;
RUN set -eu \
    ; git clone https://github.com/transmission/transmission Transmission \
    ; cd Transmission \
    ; git submodule update --init --recursive \
    ;
RUN set -eu \
    ; mkdir build \
    ; cd build \
    ;
RUN set -eu \
    ; cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DENABLE_DAEMON=ON \
      -DENABLE_QT=OFF \
      -DENABLE_UTILS=ON \
      -DENABLE_CLI=ON \
      .. \
    ;
RUN set -eu \
    ; make \
    ; make install \
    ;