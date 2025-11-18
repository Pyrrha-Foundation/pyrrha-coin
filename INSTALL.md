# Installing Pyrrha

This document explains how to install, run, and build the Pyrrha blockchain node.

Pyrrha provides two binaries:

- pyrrhad — the headless daemon
- pyrrha-qt — the GUI wallet (optional)

Binary releases will be available before testnet launch.

------------------------------------------------------------

# Downloading Pyrrha (Coming Soon)

Precompiled binaries will be published at:

https://github.com/Pyrrha-Foundation/pyrrha-coin/releases

Until then, you must build from source.

------------------------------------------------------------

# Windows

You will be able to choose between:

- Installer (.exe)
- Portable archive (.zip)

From the portable version, run:

- pyrrha-qt.exe (GUI)
- pyrrhad.exe (daemon)

(Coming soon.)

------------------------------------------------------------

# Linux / Unix

Extract the release archive (when available) and run:

GUI:
    ./bin/pyrrha-qt

Daemon:
    ./bin/pyrrhad

Data directory (blockchain + config):

    ~/.pyrrha/

------------------------------------------------------------

# macOS

Drag Pyrrha.app into your Applications folder.

(Coming soon.)

------------------------------------------------------------

# Building Pyrrha From Source

For detailed build notes, see the files in doc/build-*.md.

Below is the quick version.

------------------------------------------------------------

## 1. Install Dependencies (Ubuntu/Debian)

    sudo apt-get update
    sudo apt-get install \
      git build-essential libtool autotools-dev automake pkg-config \
      libssl-dev libevent-dev bsdmainutils libboost-all-dev

Optional dependencies for pyrrha-qt:

    sudo apt-get install \
      qttools5-dev-tools qttools5-dev libprotobuf-dev protobuf-compiler libqrencode-dev

------------------------------------------------------------

## 2. Fetch Code and Build

    git clone https://github.com/Pyrrha-Foundation/pyrrha-coin.git
    cd pyrrha-coin
    ./autogen.sh

Build daemon only (recommended for servers):

    ./configure --disable-wallet --without-gui
    make -j$(nproc)

Build with GUI:

    ./configure
    make -j$(nproc)

Optional install:

    sudo make install

This makes pyrrhad, pyrrha-cli, and pyrrha-qt available system-wide.

------------------------------------------------------------

# Quick Start

Start the daemon:

    pyrrhad -daemon

Check node status:

    pyrrha-cli getblockchaininfo

------------------------------------------------------------

# Initial Blockchain Sync

For faster sync, increase database cache.

CLI:

    pyrrhad -cache.dbcache=1000

Config file (pyrrha.conf):

    cache.dbcache=1000

------------------------------------------------------------

# Network Connectivity

Pyrrha requires inbound and outbound connections.

Forward the P2P port:

    26660

Enable UPnP (optional):

    pyrrhad -upnp=1

------------------------------------------------------------

# Wallet Options

Increase fee:

    wallet.payTxFee=0.0001

Enable automatic fee estimation:

    wallet.feeEstimation=1

Set maximum fee:

    wallet.maxTxFee=0.001

Enable instant transactions:

    wallet.instant=true

------------------------------------------------------------

# Getting Help

GitHub Issues:
    https://github.com/Pyrrha-Foundation/pyrrha-coin/issues

------------------------------------------------------------

