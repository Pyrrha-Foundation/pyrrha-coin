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


def init(libnexa_file=None):
    global libnexa
    if libnexa_file is None:
        libnexa_file = "libnexa.so"
        try:
            libnexa = CDLL(libnexa_file)
            print("Loaded %s" % libnexa_file)
        except OSError:
            import os
            dir_path = os.path.dirname(os.path.realpath(__file__))
            libnexa = CDLL(dir_path + os.sep + libnexa_file)
            print("Loaded %s" % (dir_path + os.sep + libnexa_file))
    else:
        libnexa = CDLL(libnexa_file)
        print("Loaded %s" % libnexa_file)
    if libnexa is None:
        raise Error("Cannot find %s shared library", libnexa_file)
    # NOTE: None, integers, bytes objects and (unicode) strings are the only native
    # Python objects that can directly be used as parameters in these function calls
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

    # base functions
    libnexa.libnexaVersion.restype = c_int
    libnexa.libnexaVersion.argtypes = [ ]
    libnexa.libnexa_version.restype = c_uint32
    libnexa.libnexa_version.argtypes = [ ]
    libnexa.get_libnexa_error.restype = c_uint32
    libnexa.get_libnexa_error.argtypes = [ ]
    libnexa.get_libnexa_error_string.restype = c_void_p
    libnexa.get_libnexa_error_string.argtypes = [ POINTER(c_uint32) ]
    libnexa.libnexa_free.restype = None
    libnexa.libnexa_free.argtypes = [ c_void_p ]

    # v1 api
    libnexa.encode64.restype = c_int
    libnexa.encode64.argtypes = [ c_char_p, c_int, c_char_p, c_int ]
    libnexa.decode64.restype = c_int
    libnexa.decode64.argtypes = [ c_char_p, c_char_p, c_int ]
    libnexa.Bin2Hex.restype = c_int
    libnexa.Bin2Hex.argtypes = [ c_char_p, c_int, c_char_p, c_uint ]
    libnexa.hd44DeriveChildKey.restype = c_int
    libnexa.hd44DeriveChildKey.argtypes = [ c_char_p, c_uint, c_uint, c_uint, c_uint, c_bool, c_uint, c_char_p, c_char_p ]
    libnexa.GetPubKey.restype = c_int
    libnexa.GetPubKey.argtypes = [ c_char_p, c_char_p, c_uint ]
    libnexa.SignHashEDCSA.restype = c_int
    libnexa.SignHashEDCSA.argtypes = [ c_char_p, c_int, c_char_p, c_char_p, c_int ]
    libnexa.txid.restype = c_int
    libnexa.txid.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.txidem.restype = c_int
    libnexa.txidem.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.blockHash.restype = c_int
    libnexa.blockHash.argtypes = [ c_char_p, c_int, c_char_p ]
    libnexa.SignTxECDSA.restype = c_int
    libnexa.SignTxECDSA.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_uint32, c_char_p, c_char_p, c_uint ]
    libnexa.signBchTxOneInputUsingSchnorr.restype = c_int
    libnexa.signBchTxOneInputUsingSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_uint32, c_char_p, c_char_p, c_uint ]
    libnexa.signTxOneInputUsingSchnorr.restype = c_int
    libnexa.signTxOneInputUsingSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_char_p, c_uint, c_char_p, c_char_p, c_uint ]
    libnexa.SignTxSchnorr.restype = c_int
    libnexa.SignTxSchnorr.argtypes = [ c_char_p, c_int, c_uint, c_int64, c_char_p, c_uint32, c_char_p, c_uint, c_char_p, c_char_p, c_uint ]
    libnexa.signHashSchnorr.restype = c_int
    libnexa.signHashSchnorr.argtypes = [ c_char_p, c_char_p, c_char_p ]
    libnexa.signHashSchnorrWithNonce.restype = c_int
    libnexa.signHashSchnorrWithNonce.argtypes = [ c_char_p, c_char_p, c_char_p, c_char_p ]
    libnexa.parseGroupDescription.restype = c_int
    libnexa.parseGroupDescription.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getArgsHashFromScriptPubkey.restype = c_int
    libnexa.getArgsHashFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getTemplateHashFromScriptPubkey.restype = c_int
    libnexa.getTemplateHashFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64 ]
    libnexa.getGroupTokenInfoFromScriptPubkey.restype = c_int
    libnexa.getGroupTokenInfoFromScriptPubkey.argtypes = [ c_char_p, c_uint64, c_char_p, c_uint64, POINTER(c_uint64), POINTER(c_int64) ]
    libnexa.signMessage.restype = c_int
    libnexa.signMessage.argtypes = [ c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.verifyMessage.restype = c_int
    libnexa.verifyMessage.argtypes = [ c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.verifyBlockHeader.restype = c_bool
    libnexa.verifyBlockHeader.argtypes = [ c_int, c_char_p, c_int ]
    libnexa.encodeCashAddr.restype = c_int
    libnexa.encodeCashAddr.argtypes = [ c_int, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.decodeCashAddr.restype = c_int
    libnexa.decodeCashAddr.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.decodeCashAddrContent.restype = c_int
    libnexa.decodeCashAddrContent.argtypes = [ c_int, c_char_p, c_char_p, c_int, c_char_p ]
    libnexa.serializeScript.restype = c_int
    libnexa.serializeScript.argtypes = [ c_char_p, c_uint, c_char_p, c_int ]
    libnexa.pubkeyToScriptTemplate.restype = c_int
    libnexa.pubkeyToScriptTemplate.argtypes = [ c_char_p, c_int, c_char_p, c_int ]
    libnexa.groupIdFromAddr.restype = c_int
    libnexa.groupIdFromAddr.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.groupIdToAddr.restype = c_int
    libnexa.groupIdToAddr.argtypes = [ c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.decodeWifPrivateKey.restype = c_int
    libnexa.decodeWifPrivateKey.argtypes = [ c_int, c_char_p, c_char_p, c_int ]
    libnexa.getWorkFromDifficultyBits.restype = None
    libnexa.getWorkFromDifficultyBits.argtypes = [ c_ulong, c_char_p ]
    libnexa.getDifficultyBitsFromWork.restype = c_uint
    libnexa.getDifficultyBitsFromWork.argtypes = [ c_char_p ]
    libnexa.createBloomFilter.restype = c_int
    libnexa.createBloomFilter.argtypes = [ c_char_p, c_uint, c_double, c_int, c_int, c_int, c_int, c_char_p ]
    libnexa.extractFromMerkleBlock.restype = c_int
    libnexa.extractFromMerkleBlock.argtypes = [ c_int, c_char_p, c_int, c_char_p, c_int, c_char_p, c_int ]
    libnexa.capdSolve.restype = c_int
    libnexa.capdSolve.argtypes = [ c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.capdCheck.restype = c_int
    libnexa.capdCheck.argtypes = [ c_char_p, c_uint ]
    libnexa.capdHash.restype = c_int
    libnexa.capdHash.argtypes = [ c_char_p, c_uint, c_char_p, c_uint ]
    libnexa.capdSetPowTargetHarderThanPriority.restype = c_int
    libnexa.capdSetPowTargetHarderThanPriority.argtypes = [ c_char_p, c_uint, c_double, c_char_p, c_uint ]
    libnexa.cryptAES256CBC.restype = c_int
    libnexa.cryptAES256CBC.argtypes = [ c_uint, c_char_p, c_uint, c_char_p, c_char_p, c_char_p]
    libnexa.verifyDataSchnorr.restype = c_bool
    libnexa.verifyDataSchnorr.argtypes = [ c_char_p, c_uint, c_char_p, c_int, c_char_p ]
    libnexa.verifyHashSchnorr.restype = c_bool
    libnexa.verifyHashSchnorr.argtypes = [ c_char_p, c_char_p, c_int, c_char_p ]
    libnexa.RandomBytes.restype = c_int
    libnexa.RandomBytes.argtypes = [ c_char_p, c_int ]

    #v2 api
    libnexa.bin_to_hex.restype = c_void_p
    libnexa.bin_to_hex.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.capd_check.restype = c_bool
    libnexa.capd_check.argtypes = [ c_char_p, c_uint32 ]
    libnexa.capd_hash.restype = c_void_p
    libnexa.capd_hash.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.capd_set_pow_target_harder_than_priority.restype = c_void_p
    libnexa.capd_set_pow_target_harder_than_priority.argtypes = [ c_char_p, c_uint32, c_double, POINTER(c_uint32) ]
    libnexa.capd_solve.restype = c_void_p
    libnexa.capd_solve.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.crypt_aes_256_cbc.restype = c_void_p
    libnexa.crypt_aes_256_cbc.argtypes = [ c_bool, c_char_p, c_uint32, c_char_p, c_char_p, POINTER(c_uint32) ]
    libnexa.create_bloom_filter.restype = c_void_p
    libnexa.create_bloom_filter.argtypes = [ c_char_p, c_uint32, c_double, c_uint32, c_uint32, c_int32, c_int32, POINTER(c_uint32) ]
    libnexa.decode_base64.restype = c_void_p
    libnexa.decode_base64.argtypes = [ c_char_p, POINTER(c_uint32) ]
    libnexa.decode_cash_addr.restype = c_void_p
    libnexa.decode_cash_addr.argtypes = [ c_int32, c_char_p, POINTER(c_uint32) ]
    libnexa.decode_cash_addr_content.restype = c_void_p
    libnexa.decode_cash_addr_content.argtypes = [ c_int32, c_char_p, POINTER(c_uint32), c_char_p ]
    libnexa.decode_wif_private_key.restype = c_void_p
    libnexa.decode_wif_private_key.argtypes = [ c_int32, c_char_p, POINTER(c_uint32) ]
    libnexa.encode_base64.restype = c_void_p
    libnexa.encode_base64.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.encode_cash_addr.restype = c_void_p
    libnexa.encode_cash_addr.argtypes = [ c_int32, c_int32, c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.extract_from_merkle_block.restype = c_void_p
    libnexa.extract_from_merkle_block.argtypes = [ c_int32, c_char_p, c_int32, c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.get_args_hash_from_script_pubkey.restype = c_void_p
    libnexa.get_args_hash_from_script_pubkey.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.get_difficulty_bits_from_work.restype = c_uint32
    libnexa.get_difficulty_bits_from_work.argtypes = [ c_char_p ]
    libnexa.get_group_info_from_script_pubkey.restype = c_void_p
    libnexa.get_group_info_from_script_pubkey.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32), POINTER(c_uint64), POINTER(c_int64) ]
    libnexa.get_pubkey.restype = c_void_p
    libnexa.get_pubkey.argtypes = [ c_char_p, POINTER(c_uint32) ]
    libnexa.get_template_hash_from_script_pubkey.restype = c_void_p
    libnexa.get_template_hash_from_script_pubkey.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.get_txid.restype = c_void_p
    libnexa.get_txid.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.get_txidem.restype = c_void_p
    libnexa.get_txidem.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.get_work_from_difficulty_bits.restype = c_void_p
    libnexa.get_work_from_difficulty_bits.argtypes = [ c_uint32, POINTER(c_uint32) ]
    libnexa.group_id_from_addr.restype = c_void_p
    libnexa.group_id_from_addr.argtypes = [ c_int32, c_char_p, POINTER(c_uint32) ]
    libnexa.group_id_to_addr.restype = c_void_p
    libnexa.group_id_to_addr.argtypes = [ c_int32, c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.hash160.restype = c_void_p
    libnexa.hash160.argtypes = [ c_char_p, c_uint32 ]
    libnexa.hash256.restype = c_void_p
    libnexa.hash256.argtypes = [ c_char_p, c_uint32 ]
    libnexa.hash_block_header.restype = c_void_p
    libnexa.hash_block_header.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.hd44_derive_child_key.restype = c_void_p
    libnexa.hd44_derive_child_key.argtypes = [ c_char_p, c_uint32, c_uint32, c_uint32, c_uint32, c_bool, c_uint32, POINTER(c_uint32) ]
    libnexa.parse_group_description.restype = c_void_p
    libnexa.parse_group_description.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.pubkey_to_script_template.restype = c_void_p
    libnexa.pubkey_to_script_template.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.random_bytes.restype = c_void_p
    libnexa.random_bytes.argtypes = [ c_uint32 ]
    libnexa.recover_pubkey_from_signature.restype = c_void_p
    libnexa.recover_pubkey_from_signature.argtypes = [ c_char_p, c_uint32, c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.serialise_script.restype = c_void_p
    libnexa.serialise_script.argtypes = [ c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.sha256.restype = c_void_p
    libnexa.sha256.argtypes = [ c_char_p, c_uint32 ]
    libnexa.sign_bch_tx_one_input_using_schnorr.restype = c_void_p
    libnexa.sign_bch_tx_one_input_using_schnorr.argtypes = [ c_char_p, c_uint32, c_uint32, c_int64, c_char_p, c_uint32, c_uint8, c_char_p, POINTER(c_uint32) ]
    libnexa.sign_hash_ecdsa.restype = c_void_p
    libnexa.sign_hash_ecdsa.argtypes = [ c_char_p, c_uint32, c_char_p, POINTER(c_uint32) ]
    libnexa.sign_hash_schnorr.restype = c_void_p
    libnexa.sign_hash_schnorr.argtypes = [ c_char_p, c_char_p, POINTER(c_uint32) ]
    libnexa.sign_hash_schnorr_with_nonce.restype = c_void_p
    libnexa.sign_hash_schnorr_with_nonce.argtypes = [ c_char_p, c_char_p, c_char_p, POINTER(c_uint32) ]
    libnexa.sign_message.restype = c_void_p
    libnexa.sign_message.argtypes = [ c_char_p, c_uint32, c_char_p, c_uint32, POINTER(c_uint32) ]
    libnexa.sign_tx_ecdsa.restype = c_void_p
    libnexa.sign_tx_ecdsa.argtypes = [ c_char_p, c_uint32, c_uint32, c_int64, c_char_p, c_uint32, c_uint8, c_char_p, POINTER(c_uint32) ]
    libnexa.sign_tx_one_input_using_schnorr.restype = c_void_p
    libnexa.sign_tx_one_input_using_schnorr.argtypes = [ c_char_p, c_uint32, c_uint32, c_int64, c_char_p, c_uint32, c_char_p, c_uint32, c_char_p, POINTER(c_uint32) ]
    libnexa.verify_block_header.restype = c_bool
    libnexa.verify_block_header.argtypes = [ c_int32, c_char_p, c_uint32 ]
    libnexa.verify_data_schnorr.restype = c_bool
    libnexa.verify_data_schnorr.argtypes = [ c_char_p, c_uint32, c_char_p, c_uint32, c_char_p ]
    libnexa.verify_hash_schnorr.restype = c_bool
    libnexa.verify_hash_schnorr.argtypes = [ c_char_p, c_char_p, c_uint32, c_char_p ]
    libnexa.verify_message.restype = c_bool
    libnexa.verify_message.argtypes = [ c_char_p, c_uint32, c_char_p, c_uint32, c_char_p, c_uint32 ]


# hacky fix for creating response buffers, nothing should ever be this big
C_STR_BUF_SIZE = 1000

class LIBNEXA_ERROR(IntEnum):
    SUCCESS_NO_ERROR = 0,   # success
    INVALID_ARG = 1,        # an arg is either NULL or has an invalid size
    DECODE_FAILURE = 2,     # failed to decode some array of bytes passed in
    RETURN_FAILURE = 3,     # unable to return the result for some reason
    INTERNAL_ERROR = 4,     # critical logic or implementation error somewhere

# Hack to get script machine to work without edits for now
def get_libnexa():
    return libnexa

def libnexaVersion():
    version = libnexa.libnexaVersion()
    return version

def libnexa_version():
    version = libnexa.libnexa_version()
    return version

def get_libnexa_error():
    res = libnexa.get_libnexa_error()
    return res

def get_libnexa_error_string() -> str:
    res_size = c_uint32()
    res_ptr = libnexa.get_libnexa_error_string(byref(res_size))
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    res = res_buf.decode("UTF-8").strip()
    return res

def encode64(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.encode64(input_data, len(input_data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decode64(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.decode64(input_data, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def Bin2Hex(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.Bin2Hex(input_data, len(input_data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size - 1]

def hd44DeriveChildKey(seed: bytes, purpose: int, coin_type: int, account: int, change: bool, index: int) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    null_ptr = POINTER(c_char)()
    res_size = libnexa.hd44DeriveChildKey(seed, len(seed), purpose, coin_type, account, change, index, res_buf, null_ptr)
    # secret returned is always assumed to be 32 bytes
    return res_buf.raw[0:32]

def GetPubKey(privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.GetPubKey(privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def SignHashEDCSA(input_data: bytes, privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignHashEDCSA(input_data, len(input_data), privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def txid(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.txid(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def txidem(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.txidem(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def blockHash(input_data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.blockHash(input_data, len(input_data), res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def SignTxECDSA(tx_data: bytes, input_index: int, input_amount: int,
                prevout_script: bytes, hash_type: int, privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignTxECDSA(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def signBchTxOneInputUsingSchnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signBchTxOneInputUsingSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]


def signTxOneInputUsingSchnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    if type(hash_type) == int:
        hash_type = bytes([hash_type])
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signTxOneInputUsingSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type, len(hash_type),
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def SignTxSchnorr(tx_data: bytes, input_index: int, input_amount: int,
                prevout_script: bytes, hash_type: int, privkey_bytes: bytes) -> bytes:
    if type(hash_type) == int:
        hash_type = bytes([hash_type])
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.SignTxSchnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type, len(hash_type),
                                    privkey_bytes, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def signHashSchnorr(hash: bytes, privkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signHashSchnorr(hash, privkey, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def signHashSchnorrWithNonce(hash: bytes, privkey: bytes, nonce: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signHashSchnorrWithNonce(hash, privkey, nonce, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def parseGroupDescription(op_return: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.parseGroupDescription(op_return, len(op_return), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getArgsHashFromScriptPubkey(serailised_pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.getArgsHashFromScriptPubkey(serailised_pubkey, len(serailised_pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getTemplateHashFromScriptPubkey(serailised_pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.getTemplateHashFromScriptPubkey(serailised_pubkey, len(serailised_pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getGroupTokenInfoFromScriptPubkey(serialised_pubkey: bytes) -> (bytes, int, int):
    group_id_buf = create_string_buffer(C_STR_BUF_SIZE)
    group_flags = c_ulonglong(0)
    group_amount = c_longlong(0)
    group_id_size = libnexa.getGroupTokenInfoFromScriptPubkey(serailised_pubkey, len(serailised_pubkey),
                            group_id_buf, C_STR_BUF_SIZE, pointer(group_flags), pointer(group_amount))
    if group_id_size <= 0:
        return None, None, None
    return group_id_buf.raw[0:group_id_size], group_amount.value, group_flags.value

def signMessage(privkey: bytes , msg: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.signMessage(msg, len(msg), privkey, len(privkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyMessage(addr: bytes, msg: bytes, sig: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.verifyMessage(msg, len(msg), addr, len(addr), sig, len(sig), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyBlockHeader(chain: int, serialised_header: bytes) -> bool:
    res = libnexa.verifyBlockHeader(chain, serialised_header, len(serialised_header))
    return res

def encodeCashAddr(chain: int, type: int, data: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.encodeCashAddr(chain, type, data, len(data), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decodeCashAddr(chain: int, addr: str) -> (int, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    utf8_addr = addr.encode("UTF-8")
    res_size = libnexa.decodeCashAddr(chain, utf8_addr, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return int(res_buf.raw[0]), res_buf.raw[1:res_size]

def decodeCashAddrContent(chain: int, addr: str) -> (bytes, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    addr_type = create_string_buffer(1)
    utf8_addr = addr.encode("UTF-8")
    res_size = libnexa.decodeCashAddrContent(chain, utf8_addr, res_buf, C_STR_BUF_SIZE, addr_type)
    if res_size <= 0:
        return None, None
    return addr_type.raw[0:1], res_buf.raw[0:res_size]

def serializeScript(script: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.serializeScript(script, len(script), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def pubkeyToScriptTemplate(pubkey: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.pubkeyToScriptTemplate(pubkey, len(pubkey), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def groupIdFromAddr(chain: int, addr: str) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.groupIdFromAddr(chain, addr, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def groupIdToAddr(chain: int, group_id: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.groupIdToAddr(chain, group_id, len(group_id), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def decodeWifPrivateKey(chain: int, wif_string: str) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.decodeWifPrivateKey(chain, wif_string, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def getWorkFromDifficultyBits(bits: int) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    c_bits = c_ulong(bits)
    libnexa.getWorkFromDifficultyBits(c_bits, res_buf)
    return res_buf.raw[0:32]

def getDifficultyBitsFromWork(work_bytes: bytes) -> int:
    res = libnexa.getDifficultyBitsFromWork(work_bytes)
    return res

def createBloomFilter(data: bytes, false_pos_rate: float, capacity: int, max_size: int, flags: int, tweak: int) -> bytes:
    res_buf = create_string_buffer(max_size)
    res_size = libnexa.createBloomFilter(data, len(data), false_pos_rate, capacity, max_size, flags, tweak, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def extractFromMerkleBlock(num_txes: int, merkle_proof_path: bytes, hash_in: bytes, num_hashes: int) -> (int, bytes):
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res = libnexa.extractFromMerkleBlock(num_txes, merkle_proof_path, len(merkle_proof_path),
                                        hash_in, len(hash_in), num_hashes, res_buf, C_STR_BUF_SIZE)
    return int(res), res_buf.raw[0:(res*32)]

def capdSolve(message: bytes) -> bytes:
    res_size_buf = create_string_buffer(C_STR_BUF_SIZE)
    res = libnexa.capdSolve(message, len(message), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def capdCheck(message: bytes) -> bool:
    return libnexa.capdCheck(message, len(message))

def capdHash(message: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.capdHash(message, len(message), res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def capdSetPowTargetHarderThanPriority(message: bytes, priority: float) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.capdSetPowTargetHarderThanPriority(message, len(message), priority, res_buf, C_STR_BUF_SIZE)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def cryptAES256CBC(encrypt: int, data: bytes, privkey: bytes, iv: bytes) -> bytes:
    res_buf = create_string_buffer(C_STR_BUF_SIZE)
    res_size = libnexa.cryptAES256CBC(encrypt, data, len(data), privkey, iv, res_buf)
    if res_size <= 0:
        return None
    return res_buf.raw[0:res_size]

def verifyDataSchnorr(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verifyDataSchnorr(message, len(message), pubkey, len(pubkey), signature)
    return bool(res)

def verifyHashSchnorr(hash: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verifyHashSchnorr(hash, pubkey, len(pubkey), signature)
    return bool(res)

def RandomBytes(num_bytes: int) -> bytes:
    res_buf = create_string_buffer(num_bytes)
    res_size = libnexa.RandomBytes(res_buf, num_bytes)
    return res_buf.raw[0:res_size]


# v2 API

def bin_to_hex(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.bin_to_hex(input_data, len(input_data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    return res_buf

def capd_check(message: bytes) -> bool:
    return libnexa.capd_check(message, len(message))

def capd_hash(message: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.capd_hash(message, len(message), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def capd_set_pow_target_harder_than_priority(message: bytes, priority: float) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.capd_set_pow_target_harder_than_priority(message, len(message), priority, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def capd_solve(message: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.capd_solve(message, len(message), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def crypt_aes_256_cbc(encrypt: int, data: bytes, privkey: bytes, iv: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.crypt_aes_256_cbc(encrypt, data, len(data), privkey, iv, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def create_bloom_filter(data: bytes, false_pos_rate: float, capacity: int, max_size: int, flags: int, tweak: int) -> bytes:
    res_size = c_uint32(max_size)
    res_ptr = libnexa.create_bloom_filter(data, len(data), false_pos_rate, capacity, max_size, flags, tweak, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def decode_base64(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.decode_base64(input_data, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    return res_buf

def decode_cash_addr(chain: int, addr: str) -> (int, bytes):
    res_size = c_uint32()
    utf8_addr = addr.encode("UTF-8")
    res_ptr = libnexa.decode_cash_addr(chain, utf8_addr, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    addr_type = int(res_buf[0])
    res_buf = res_buf[1:res_size.value]
    libnexa.libnexa_free(res_ptr)
    return addr_type, res_buf

def decode_cash_addr_content(chain: int, addr: str) -> (int, bytes):
    res_size = c_uint32()
    p_addr_type = create_string_buffer(1)
    utf8_addr = addr.encode("UTF-8")
    res_ptr = libnexa.decode_cash_addr_content(chain, utf8_addr, byref(res_size), p_addr_type)
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None, None
    addr_type = int.from_bytes(p_addr_type.raw[0:1])
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return addr_type, res_buf

def decode_wif_private_key(chain: int, wif_string: str) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.decode_wif_private_key(chain, wif_string, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def encode_base64(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.encode_base64(input_data, len(input_data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    return res_buf

def encode_cash_addr(chain: int, type: int, data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.encode_cash_addr(chain, type, data, len(data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    return res_buf

def extract_from_merkle_block(num_txes: int, merkle_proof_path: bytes, hash_in: bytes, num_hashes: int) -> (int, bytes):
    res_size = c_uint32()
    res_ptr = libnexa.extract_from_merkle_block(num_txes, merkle_proof_path, len(merkle_proof_path),
                                        hash_in, len(hash_in), num_hashes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return 0, None
    ret_hashes = int(res_size / 32)
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return ret_hashes, res_buf

def get_args_hash_from_script_pubkey(serailised_pubkey: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_args_hash_from_script_pubkey(serailised_pubkey, len(serailised_pubkey), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def get_difficulty_bits_from_work(work_bytes: bytes) -> int:
    res = libnexa.get_difficulty_bits_from_work(work_bytes)
    return res

def get_group_info_from_script_pubkey(serialised_pubkey: bytes) -> (bytes, int, int):
    group_id_size = c_uint32()
    group_flags = c_ulonglong(0)
    group_amount = c_longlong(0)
    group_id_ptr = libnexa.get_group_info_from_script_pubkey(serailised_pubkey, len(serailised_pubkey),
                            byref(group_id_size), byref(group_flags), byref(group_amount))
    if group_id_size <= 0:
        libnexa.libnexa_free(group_id_ptr)
        return None, None, None
    group_id_buf = group_id_ptr.raw[0:group_id_size]
    libnexa.libnexa_free(group_id_ptr)
    return group_id_buf, group_amount.value, group_flags.value

def get_pubkey(privkey_bytes: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_pubkey(privkey_bytes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def get_template_hash_from_script_pubkey(serailised_pubkey: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_template_hash_from_script_pubkey(serailised_pubkey, len(serailised_pubkey), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def get_txid(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_txid(input_data, len(input_data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def get_txidem(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_txidem(input_data, len(input_data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def get_work_from_difficulty_bits(bits: int) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.get_work_from_difficulty_bits(bits, byref(res_size))
    res_buf = string_at(res_ptr, 32)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def group_id_from_addr(chain: int, addr: str) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.group_id_from_addr(chain, addr, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def group_id_to_addr(chain: int, group_id: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.group_id_to_addr(chain, group_id, len(group_id), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value - 1) # -1 to trim null term, python strings are not null terminated
    libnexa.libnexa_free(res_ptr)
    return res_buf

def hash160(data: bytes) -> bytes:
    res_ptr = libnexa.hash160(data, len(data))
    res_buf = string_at(res_ptr, 20)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def hash256(data: bytes) -> bytes:
    res_ptr = libnexa.hash256(data, len(data))
    res_buf = string_at(res_ptr, 32)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def hash_block_header(input_data: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.hash_block_header(input_data, len(input_data), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def hd44_derive_child_key(seed: bytes, purpose: int, coin_type: int, account: int, change: bool, index: int) -> bytes:
    res_size = c_uint32()
    null_ptr = POINTER(c_char)()
    res_ptr = libnexa.hd44_derive_child_key(seed, len(seed), purpose, coin_type, account, change, index, byref(res_size), null_ptr)
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def parse_group_description(op_return: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.parse_group_description(op_return, len(op_return), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def pubkey_to_script_template(pubkey: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.pubkey_to_script_template(pubkey, len(pubkey), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def random_bytes(num_bytes: int) -> bytes:
    res_ptr = libnexa.random_bytes(num_bytes)
    res_buf = string_at(res_ptr, num_bytes)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def recover_pubkey_from_signature(msg: bytes, sig: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.recover_pubkey_from_signature(msg, len(msg), sig, len(sig), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def serialise_script(script: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.serialise_script(script, len(script), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sha256(data: bytes) -> bytes:
    res_ptr = libnexa.sha256(data, len(data))
    res_buf = string_at(res_ptr, 32)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_bch_tx_one_input_using_schnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_bch_tx_one_input_using_schnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_hash_ecdsa(input_data: bytes, privkey_bytes: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_hash_ecdsa(input_data, len(input_data), privkey_bytes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_hash_schnorr(hash: bytes, privkey: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_hash_schnorr(hash, privkey, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_hash_schnorr_with_nonce(hash: bytes, privkey: bytes, nonce: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_hash_schnorr_with_nonce(hash, privkey, nonce, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_message(privkey: bytes , msg: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_message(msg, len(msg), privkey, len(privkey), byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_tx_ecdsa(tx_data: bytes, input_index: int, input_amount: int,
                prevout_script: bytes, hash_type: int, privkey_bytes: bytes) -> bytes:
    res_size = c_uint32()
    res_ptr = libnexa.sign_tx_ecdsa(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type,
                                    privkey_bytes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def sign_tx_one_input_using_schnorr(tx_data: bytes, input_index: int,
                input_amount: int, prevout_script: bytes, hash_type: int,
                privkey_bytes: bytes) -> bytes:
    if type(hash_type) == int:
        hash_type = bytes([hash_type])
    res_size = c_uint32()
    res_ptr = libnexa.sign_tx_one_input_using_schnorr(tx_data, len(tx_data), input_index, input_amount,
                                    prevout_script, len(prevout_script), hash_type, len(hash_type),
                                    privkey_bytes, byref(res_size))
    if res_size.value <= 0:
        libnexa.libnexa_free(res_ptr)
        return None
    res_buf = string_at(res_ptr, res_size.value)
    libnexa.libnexa_free(res_ptr)
    return res_buf

def verify_block_header(chain: int, serialised_header: bytes) -> bool:
    res = libnexa.verify_block_header(chain, serialised_header, len(serialised_header))
    return bool(res)

def verify_data_schnorr(message: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verify_data_schnorr(message, len(message), pubkey, len(pubkey), signature)
    return bool(res)

def verify_hash_schnorr(hash: bytes, pubkey: bytes, signature: bytes) -> bool:
    res = libnexa.verifyHashSchnorr(hash, pubkey, len(pubkey), signature)
    return bool(res)

def verify_message(addr: bytes, msg: bytes, sig: bytes) -> bytes:
    res = libnexa.verify_message(msg, len(msg), addr, len(addr), sig, len(sig))
    return bool(res)
