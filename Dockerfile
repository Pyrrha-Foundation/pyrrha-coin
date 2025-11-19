FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (including GMP)
RUN apt-get update && \
    apt-get install -y \
      build-essential \
      libtool \
      autotools-dev \
      automake \
      pkg-config \
      bsdmainutils \
      libevent-dev \
      libboost-all-dev \
      libssl-dev \
      libzmq3-dev \
      libdb-dev \
      libdb++-dev \
      libgmp-dev \
      git \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy your local source tree into the image
COPY . .

# Build Pyrrha completely inside the container, with LOW parallelism
RUN ./autogen.sh && \
    ./configure --disable-tests --disable-bench && \
    make -j16

CMD ["bash"]
