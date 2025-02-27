# Copyright (c) 2018-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from ctypes import *
from test_framework.nodemessages import *
from test_framework.constants import *
from test_framework.ripemd160 import *
from test_framework.util import findBitcoind
from binascii import hexlify, unhexlify
from enum import IntEnum, IntFlag
import pdb
import hashlib
import decimal
import platform
import os

libnexa = None

def loadLibNexaOrExit(srcdir=None):
    try:
        path = findBitcoind(srcdir)
        init(path + os.sep + ".libs" + os.sep + "libnexa.so")
    except OSError as e:
        p = platform.platform()
        print("Platform  : " + p)
        if "Linux" in p and "x86_64" in p: raise  # libnexa should be created on this platform
        print("Issue loading shared library.  This is expected during cross compilation since the native python will not load the .so: %s" % str(e))
        exit(0)

# match this with values in libnexa_common.h
class PayAddressType(IntEnum):
    PayAddressTypeP2PKH = 0
    PayAddressTypeP2SH = 1
    PayAddressTypeGROUP = 11
    PayAddressTypeTEMPLATE = 19
    PayAddressTypeNONE = 255

class ChainSelector(IntEnum):
    AddrBlockchainNexa = 1
    AddrBlockchainTestnet = 2
    AddrBlockchainRegtest = 3
    AddrBlockchainBCH = 4
    AddrBlockchainBchTestnet = 5
    AddrBlockchainBchRegtest = 6

REGTEST = ChainSelector.AddrBlockchainRegtest

class Error(BaseException):
    pass


def init(libbitcoincashfile=None):
    global libnexa
    if libbitcoincashfile is None:
        libbitcoincashfile = "libnexa.so"
        try:
            libnexa = CDLL(libbitcoincashfile)
            print("Loaded %s" % libbitcoincashfile)
        except OSError:
            import os
            dir_path = os.path.dirname(os.path.realpath(__file__))
            libnexa = CDLL(dir_path + os.sep + libbitcoincashfile)
            print("Loaded %s" % (dir_path + os.sep + libbitcoincashfile))
    else:
        libnexa = CDLL(libbitcoincashfile)
        print("Loaded %s" % libbitcoincashfile)
    if libnexa is None:
        raise Error("Cannot find %s shared library", libbitcoincashfile)
    libnexa.CreateNoContextScriptMachine.restype = c_void_p
    libnexa.CreateScriptMachine.restype = c_void_p
    libnexa.CreateScriptMachine.argtypes = [ c_int, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.SmEval.argtypes = [ c_void_p, c_char_p, c_int]
    libnexa.SmBeginStep.argtypes = [ c_void_p, c_char_p, c_int]
    libnexa.SmClone.argtypes = [ c_void_p ]
    libnexa.SmClone.restype = c_void_p
    libnexa.SmRelease.argtypes = [ c_void_p ]
    libnexa.SmReset.argtypes = [ c_void_p ]
    libnexa.SmStep.argtypes = [ c_void_p ]
    libnexa.SmPos.argtypes = [ c_void_p ]
    libnexa.SmGetError.argtypes = [ c_void_p ]
    libnexa.SmEndStep.argtypes = [ c_void_p ]
    libnexa.SmGetStackItem.argtypes = [ c_void_p, c_int, c_int, c_char_p, c_char_p ]
    libnexa.SmSetStackItem.argtypes = [ c_void_p, c_int, c_int, c_int, c_char_p, c_int ]
