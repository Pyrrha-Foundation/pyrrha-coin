// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PYRRHA_ZMQ_ZMQCONFIG_H
#define PYRRHA_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include "pyrrha-config.h"
#endif

#include <stdarg.h>
#include <string>

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include "primitives/block.h"
#include "primitives/transaction.h"

void zmqError(const char *str);

#endif // PYRRHA_ZMQ_ZMQCONFIG_H
