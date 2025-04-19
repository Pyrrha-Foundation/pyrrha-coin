#!/usr/bin/env python3
# Copyright (c) 2015-2022 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import json
import test_framework.loginit
import time
import sys
import copy
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
import enum

from ctypes import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import test_framework.util as util
import test_framework.libnexa as libnexa
import test_framework.libnexa.verify_test_coverage as libnexa_test_coverage
from test_framework.nodemessages import *
from test_framework.script import *

C_STR_BUF_SIZE = 1000

class LibnexaTest(BitcoinTestFramework):

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        libnexa.loadLibNexaOrExit(self.options.srcdir)
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def test_libnexaVersion(self):
        version = libnexa.libnexaVersion()
        return version

    def test_libnexa_version(self):
        version = libnexa.libnexa_version()
        return version

    def test_libnexa_free(self):
        # this is tested in every v2 api call internally
        pass

    def test_get_libnexa_error(self):
        template = bytes.fromhex("17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        # should fail
        res = libnexa.getArgsHashFromScriptPubkey(template)
        assert res == None
        # get error code
        res = libnexa.get_libnexa_error()
        assert res == 2
        return res

    def test_get_libnexa_error_string(self):
        template = bytes.fromhex("17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        # should fail
        res = libnexa.getArgsHashFromScriptPubkey(template)
        assert res == None
        # get error string
        res = libnexa.get_libnexa_error_string()
        expected_error = "Decode failure: failed to get script template from script provided"
        # do this because v1 api does not know how long returned error string is
        # because the user creates the space for it, not the library
        assert res[0:len(expected_error)] == expected_error
        return res[0:len(expected_error)]

    def test_libnexa_errors(self):
        pass

    def test_encode64(self):
        test_data = "This is a test string.".encode(encoding="UTF-8")
        res = libnexa.encode64(test_data)
        assert res == b"VGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg=="
        return res

    def test_decode64(self):
        test_data = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg==".encode(encoding="UTF-8")
        res = libnexa.decode64(test_data)
        assert res == b"This is a test string."
        return res

    def test_Bin2Hex(self):
        # bytes.fromhex goes from hex to binary, opposite of Bin2Hex
        test_data = bytes.fromhex("5D5478AB")
        res = libnexa.Bin2Hex(test_data)
        # result is returned with null term char
        assert res == b"5D5478AB\0"
        return res

    def test_hd44DeriveChildKey(self):
        #master_key = "cUj4SSY3WPYtwghGz7xVmhE6T6nyH2AHyLpPsMHNSPrTxqTmuuzs"
        master_key = bytes.fromhex("d52964419a5994799ddf80fac88a92ef926339cb009f5ebc2e5c345320b7e8a4")
        purpose = 44
        coin_type = 29223
        account = 0
        change = False
        index = 1
        res = libnexa.hd44DeriveChildKey(master_key, purpose, coin_type, account, change, index)
        child_key = res.hex()
        assert child_key == "3d078d4e940799e2cc3deca407fe1eba20f68b5c72de8e9e4e061958a29d0b0e"
        return child_key


    def test_SignHashEDCSA(self):
        pass

    def test_GetPubKey(self):
        privkey_bytes = bytes.fromhex("1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4")
        res = libnexa.GetPubKey(privkey_bytes)
        pubkey = res.hex()
        assert pubkey == "03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea"
        return pubkey

    def test_txid(self):
        # random real transaction
        # https://explorer.nexa.org/tx/bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e
        test_data = bytes.fromhex("000100350b6a02bd95250365eb02799073d8c734817f" +
        "a93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f" +
        "0e09a59ac083b0b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a" +
        "88688ef31d0bd9534ecaae3b84054dc5920852e918068dfd31f8c951bcf854d19d3f948" +
        "ff1dc362e5cbe65feffffff7f88b32b000000000401f9e31f000000000017005114aeff" +
        "40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005114fcc9a546f" +
        "cb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a4671" +
        "3fe8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874" +
        "393870b95028e5d31492679570b00")
        res = libnexa.txid(test_data)
        # the returned bytes are in little endian, txid is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e"
        return res_bytes.hex()

    def test_txidem(self):
        # random real transaction
        # https://explorer.nexa.org/tx/bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e
        test_data = bytes.fromhex("000100350b6a02bd95250365eb02799073d8c734817f" +
        "a93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f" +
        "0e09a59ac083b0b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a" +
        "88688ef31d0bd9534ecaae3b84054dc5920852e918068dfd31f8c951bcf854d19d3f948" +
        "ff1dc362e5cbe65feffffff7f88b32b000000000401f9e31f000000000017005114aeff" +
        "40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005114fcc9a546f" +
        "cb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a4671" +
        "3fe8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874" +
        "393870b95028e5d31492679570b00")
        res = libnexa.txidem(test_data)
        # the returned bytes are in little endian, txidem is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "0918083bc948fd652bbe506debac1e3dd531b792e3a4113351da9c911dd7b222"
        return res_bytes.hex()

    def test_blockHash(self):
        # random real block
        # https://explorer.nexa.org/block/225ba0029d19886988801c540821cdd7ba592d0f74f3076d914cdbdbbf4929e7
        test_data = bytes.fromhex("b0a68bf93c899741459f84d87dc398b1c6fedcde603aee4f9f4d93b0232" +
        "108fd00606b1af0fdbc690eb9ad00a5fd4efeddb91a3b3ca6bba3d7453920e511196faa4a516d416684da0" +
        "400d3971f705f83d3453aed66fb753bb8af38a72937c90656b0d4ab0000000000000000000000000000000" +
        "0000000000000000000000000000000000d1fc067acad7b1689085115cb573521000000000000000000000" +
        "00000000000000000000000001602000000000000020000001035440e4300004c00000000000012b9c6020" +
        "00002011dcb9a3b0000000017005114009b6557e49ced88ae43f460951314dc3cd7f8c0000000000000000" +
        "0000f6a037b570b0008000000000000000000000000000100350b6a02bd95250365eb02799073d8c734817" +
        "fa93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f0e09a59ac083b0" +
        "b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a88688ef31d0bd9534ecaae3b84054" +
        "dc5920852e918068dfd31f8c951bcf854d19d3f948ff1dc362e5cbe65feffffff7f88b32b000000000401f" +
        "9e31f000000000017005114aeff40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005" +
        "114fcc9a546fcb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a46713fe" +
        "8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874393870b95028e5d31492679570b00")
        res = libnexa.blockHash(test_data)
        # the returned bytes are in little endian, txidem is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "225ba0029d19886988801c540821cdd7ba592d0f74f3076d914cdbdbbf4929e7"
        return res_bytes.hex()

    def test_SignTxECDSA(self):
        pass

    def test_signBchTxOneInputUsingSchnorr(self):
        pass

    def test_signTxOneInputUsingSchnorr(self):
        tx_data = bytes.fromhex("0001002e203c16a4104613a60c3106f8dfb9b91542f0752cd6754302da44551b26c8a700ffffffff00e1f50500000000010038e0f505000000001976a9141f5dfc518bd18c2844e22975e58138bda9df8d4f88ac00000000")
        input_index = 0
        input_amount = 100000000
        script_pubkey = bytes.fromhex("76a914ceedd4ef1ea3f69b29f7cbf9f7e1b76378fe9c9f88ac")
        key = bytes.fromhex("3d8223f5cba7e6815e10bf250d61bb9e259b1c1f3f5fe2b16f4b79177083d282")
        sig_hash_type = 0
        sig = libnexa.signTxOneInputUsingSchnorr(tx_data, input_index, input_amount, script_pubkey, sig_hash_type, key)
        assert sig == bytes.fromhex("b2facec4090be661e019726fb45b60b646de89c026c875372d621c90ac7a182b71b7189007dd7ac4ed901cc392e57556a67c8a2ec056fcca7cbaf7fe2881bdf2")
        return sig

    def test_SignTxSchnorr(self):
        tx_data = bytes.fromhex("0001002e203c16a4104613a60c3106f8dfb9b91542f0752cd6754302da44551b26c8a700ffffffff00e1f50500000000010038e0f505000000001976a9141f5dfc518bd18c2844e22975e58138bda9df8d4f88ac00000000")
        input_index = 0
        input_amount = 100000000
        script_pubkey = bytes.fromhex("76a914ceedd4ef1ea3f69b29f7cbf9f7e1b76378fe9c9f88ac")
        key = bytes.fromhex("3d8223f5cba7e6815e10bf250d61bb9e259b1c1f3f5fe2b16f4b79177083d282")
        sig_hash_type = 0
        sig = libnexa.SignTxSchnorr(tx_data, input_index, input_amount, script_pubkey, sig_hash_type, key)
        assert sig == bytes.fromhex("b2facec4090be661e019726fb45b60b646de89c026c875372d621c90ac7a182b71b7189007dd7ac4ed901cc392e57556a67c8a2ec056fcca7cbaf7fe2881bdf2")
        return sig

    def test_signHashSchnorr(self):
        privkey = bytes.fromhex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
        hash = bytes.fromhex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")
        sig = libnexa.signHashSchnorr(hash, privkey)
        assert sig == bytes.fromhex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d0717571846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce")
        return sig

    def test_signHashSchnorrWithNonce(self):
        privkey = bytes.fromhex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
        hash = bytes.fromhex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")
        nonce = bytes.fromhex("6b0c7b03bd0576678cfdf5fa56d9a7165fe6a0097a673c15d1ada69cda6fcb35")
        sig = libnexa.signHashSchnorrWithNonce(hash, privkey, nonce)
        assert sig == bytes.fromhex("fd3c6681c1540d5a7993bcf00114688dd897501a6d36cbac1bb6a2914cfb8bcf22d3b0b437d5f09b219b51dab75af5f27069b78f3dbae04239ea51ecce407927")
        return sig

    def test_parseGroupDescription(self):
        op_return_script = bytes.fromhex("6a0438564c0504415641530a417661277320436173681b68747470733a2f2f617661732e636173682f617661732e6a736f6e20780af03039b3c129374cb6cd133107ac5371a4bd659c22a93730e2495c227aaa58")
        res = libnexa.parseGroupDescription(op_return_script)
        op_return = res.decode("UTF-8")
        op_return = op_return[:-1] # remove trailing \n to make valid json object
        op_return = json.loads(op_return)
        expected_result = json.loads('{"ticker":"AVAS","name":"Ava\'s Cash","url":"https://avas.cash/avas.json","hash":"aa7a225c49e23037a9229c65bda47153ac073113cdb64c3729c1b33930f00a78","decimals":"8"}')
        assert op_return == expected_result
        return op_return

    def test_getArgsHashFromScriptPubkey(self):
        template = bytes.fromhex("005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        res = libnexa.getArgsHashFromScriptPubkey(template)
        args_hash = res.hex()
        assert args_hash == "b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return args_hash

    def test_getTemplateHashFromScriptPubkey(self):
        pass

    def test_getGroupTokenInfoFromScriptPubkey(self):
        pass

    def test_signMessage(self):
        msg = "this is a test msg".encode(encoding="UTF-8")
        privkey = bytes.fromhex("1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4")
        res = libnexa.signMessage(privkey, msg)
        sig = res.hex()
        assert sig == "2053a42ef1f7429b42e4b8676d8d6ce6fce716b43b2fa8580711822a7cff6aa83d492792db46cd79d39ccfae43a314473674e16153a277d2d1aaf0ba6014ca3df5"
        return sig

    def test_verifyMessage(self):
        pubkey = bytes.fromhex("03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea")
        pubkey_hash160 = libnexa.hash160(pubkey)
        msg = "this is a test msg".encode(encoding="UTF-8")
        sig = bytes.fromhex("2053a42ef1f7429b42e4b8676d8d6ce6fce716b43b2fa8580711822a7cff6aa83d492792db46cd79d39ccfae43a314473674e16153a277d2d1aaf0ba6014ca3df5")
        res = libnexa.verifyMessage(pubkey_hash160, msg, sig)
        found_pubkey = res.hex()
        assert found_pubkey == "03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea"
        return found_pubkey

    def test_verifyBlockHeader(self):
        # random real mainnet block header 745745
        block_header = bytes.fromhex("3a048aa4e23d9f1e81f7d9e3dcd5dd9a137fb5b5eb9cbdd9cf3319e576b23bff4084761a2f6dedb66931b04894a00532d29cf001a0ed311093bd094e659beadf916d93e6de2fd38830dff43c2e39fb7a7abed4d15a071f1284d4c39a6f419fe54eb311040000000000000000000000000000000000000000000000000000000000000000ecfcc467acc111f3d2f1792fd7014b210000000000000000000000000000000000000000000000f90000000000000001000000102d94e7630000010000000000001322dd")
        res = libnexa.verifyBlockHeader(1, block_header)
        assert res == True
        return res

    def test_encodeCashAddr(self):
        chain = 3
        type = 19
        data = bytes.fromhex("17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        res = libnexa.encodeCashAddr(chain, type, data)
        addr = res.decode("utf-8")
        assert addr == "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        return addr

    def test_decodeCashAddr(self):
        chain = 3
        data = "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        type, res = libnexa.decodeCashAddr(chain, data)
        assert type == 19
        assert res.hex() == "17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return type, res.hex()

    def test_decodeCashAddrContent(self):
        chain = 3
        data = "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        type, res = libnexa.decodeCashAddr(chain, data)
        assert type == 19
        assert res.hex() == "17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return type, res.hex()

    def test_serializeScript(self):
        script = bytes.fromhex("005114e426dcecf04bb25eb6d5394017fe29cc62ccc325")
        res = libnexa.serializeScript(script)
        assert res.hex() == "17005114e426dcecf04bb25eb6d5394017fe29cc62ccc325"
        return res.hex()

    def test_pubkeyToScriptTemplate(self):
        pubkey = bytes.fromhex("03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea")
        res = libnexa.pubkeyToScriptTemplate(pubkey)
        assert res.hex() == "005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return res.hex()

    def test_groupIdFromAddr(self):
        # real mainnet token avas cash
        # expected id taken from rostrum output on explorer
        # https://explorer.nexa.org/token/nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x
        chain = 1
        addr = "nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x".encode(encoding="UTF-8")
        res = libnexa.groupIdFromAddr(chain, addr)
        token_id_hex = res.hex()
        assert token_id_hex == "57f46c1766dc0087b207acde1b3372e9f90b18c7e67242657344dcd2af660000"
        return token_id_hex

    def test_groupIdToAddr(self):
        # real mainnet token avas cash
        # expected id taken from rostrum output on explorer
        # https://explorer.nexa.org/token/nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x
        chain = 1
        group_id = bytes.fromhex("57f46c1766dc0087b207acde1b3372e9f90b18c7e67242657344dcd2af660000")
        res = libnexa.groupIdToAddr(chain, group_id)
        addr = res.decode("UTF-8")
        assert addr == "nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x"
        return addr

    def test_decodeWifPrivateKey(self):
        chain = 3
        privkey = "cNaZtFp6sXP9obVngKwE5VpxJvZnua4XNorDpAfHaqUJ4KHXFZJ6".encode(encoding="UTF-8")
        res = libnexa.decodeWifPrivateKey(chain, privkey)
        privkey = res.hex()
        assert privkey == "1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4"
        return privkey

    def test_sha256(self):
        test_data = "SHA256 is considered to be safe".encode(encoding="UTF-8")
        res = libnexa.sha256(test_data)
        # check against expected
        assert res.hex() == "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630"
        # compare to python crypto
        assert res.hex() == util.sha256(test_data).hex()
        return res.hex()

    def test_hash256(self):
        test_data = "double SHA256 is considered to be safe".encode(encoding="UTF-8")
        res = libnexa.hash256(test_data)
        # check against expected
        assert res.hex() == "63e29a9e5de55b651a3592949cb389c92ff1c655d77e72b8dcd76c5579114067"
        # compare to python crypto
        assert res.hex() == util.hash256(test_data).hex()
        return res.hex()

    def test_hash160(self):
        test_data = "hash160 is used for addresses".encode(encoding="UTF-8")
        res = libnexa.hash160(test_data)
        # check against expected
        assert res.hex() == "900d6dd23c74f11cadfa1f519dff6be8d9d13fcd"
        # compare to python crypto
        assert res.hex() == util.hash160(test_data).hex()
        return res.hex()

    def test_getWorkFromDifficultyBits(self):
        bits = int("0x1b00954a", 16)
        res = libnexa.getWorkFromDifficultyBits(bits)
        work_bytes = res.hex()
        assert work_bytes == "0000000000000000000000000000000000000000000000000001b6fcbe9c2e23"
        return work_bytes

    def test_getDifficultyBitsFromWork(self):
        work_bytes = bytes.fromhex("232e9cbefcb60100000000000000000000000000000000000000000000000000")
        res = libnexa.getDifficultyBitsFromWork(work_bytes)
        difficulty = res
        assert difficulty == 453023050
        return difficulty

    def test_createBloomFilter(self):
        pass

    def test_extractFromMerkleBlock(self):
        pass

    def test_capdSolve(self):
        pass

    def test_capdCheck(self):
        pass

    def test_capdHash(self):
        pass

    def test_capdSetPowTargetHarderThanPriority(self):
        pass

    def test_cryptAES256CBC(self):
        encrypt = 1
        msg = "We're blown. Run".encode(encoding="UTF-8")
        key = bytes.fromhex("3d8223f5cba7e6815e10bf250d61bb9e259b1c1f3f5fe2b16f4b79177083d282")
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        encrypted_bytes = libnexa.cryptAES256CBC(encrypt, msg, key, iv)
        assert encrypted_bytes == bytes.fromhex("90bf29d1dee430a0a8fdbf6479431509")
        # now decrypt
        encrypt = 0
        decrypted_bytes = libnexa.cryptAES256CBC(encrypt, encrypted_bytes, key, iv)
        assert decrypted_bytes == msg
        return encrypted_bytes, decrypted_bytes

    def test_verifyDataSchnorr(self):
        msg = "Very secret message 0: 11".encode(encoding="UTF-8")
        pubkey = bytes.fromhex("040B4C866585DD868A9D62348A9CD008D6A312937048FFF31670E7E920CFC7A7447B5F0BBA9E01E6FE4735C8383E6E7A3347A0FD72381B8F797A19F694054E5A69")
        sig = bytes.fromhex("B6E0D8588BFDFE8B29F4CDF87621BFEF9C2B4258B5AF765C61957392B017739F3881FE4ABB0FDC8ADF766E1D8476A23D4FF191EDF54578FC2D1117DC72FE0375")
        res = libnexa.verifyDataSchnorr(msg, pubkey, sig)
        assert res == True
        return res

    def test_verifyHashSchnorr(self):
        hash = bytes.fromhex("b4f57530dbbf61c572d2eba40cac9819a70613c0b609526e3283dd5f4a5a46a4")
        pubkey = bytes.fromhex("040B4C866585DD868A9D62348A9CD008D6A312937048FFF31670E7E920CFC7A7447B5F0BBA9E01E6FE4735C8383E6E7A3347A0FD72381B8F797A19F694054E5A69")
        sig = bytes.fromhex("B6E0D8588BFDFE8B29F4CDF87621BFEF9C2B4258B5AF765C61957392B017739F3881FE4ABB0FDC8ADF766E1D8476A23D4FF191EDF54578FC2D1117DC72FE0375")
        res = libnexa.verifyHashSchnorr(hash, pubkey, sig)
        assert res == True
        return res

    def test_RandomBytes(self):
        num_bytes = 32
        res = libnexa.RandomBytes(num_bytes)
        assert len(res) == num_bytes
        random_bytes = res
        # check that the bytes are not the same 0 initalised array that
        # was made with create_string_buffer
        assert random_bytes != b"0000000000000000000000000000000000000000000000000000000000000000"
        res = libnexa.RandomBytes(num_bytes)
        assert len(res) == num_bytes
        random_bytes2 = res
        assert random_bytes2 != b"0000000000000000000000000000000000000000000000000000000000000000"
        assert random_bytes != random_bytes2
    # end v1 tests





    # begin v2 tests
    def test_encode_base64(self):
        test_data = "This is a test string.".encode(encoding="UTF-8")
        res = libnexa.encode_base64(test_data)
        assert res == b"VGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg=="
        return res

    def test_decode_base64(self):
        test_data = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nLg==".encode(encoding="UTF-8")
        res = libnexa.decode_base64(test_data)
        assert res == b"This is a test string."
        return res

    def test_bin_to_hex(self):
        # bytes.fromhex goes from hex to binary, opposite of bin_to_hex
        test_data = bytes.fromhex("5D5478AB")
        res = libnexa.bin_to_hex(test_data)
        assert res == b"5D5478AB"
        return res

    def test_hd44_derive_child_key(self):
        #master_key = "cUj4SSY3WPYtwghGz7xVmhE6T6nyH2AHyLpPsMHNSPrTxqTmuuzs"
        master_key = bytes.fromhex("d52964419a5994799ddf80fac88a92ef926339cb009f5ebc2e5c345320b7e8a4")
        purpose = 44
        coin_type = 29223
        account = 0
        change = False
        index = 1
        res = libnexa.hd44_derive_child_key(master_key, purpose, coin_type, account, change, index)
        child_key = res.hex()
        assert child_key == "3d078d4e940799e2cc3deca407fe1eba20f68b5c72de8e9e4e061958a29d0b0e"
        return child_key

    def test_sign_hash_ecdsa(self):
        pass

    def test_get_pubkey(self):
        privkey_bytes = bytes.fromhex("1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4")
        res = libnexa.get_pubkey(privkey_bytes)
        pubkey = res.hex()
        assert pubkey == "03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea"
        return pubkey

    def test_get_txid(self):
        # random real transaction
        # https://explorer.nexa.org/tx/bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e
        test_data = bytes.fromhex("000100350b6a02bd95250365eb02799073d8c734817f" +
        "a93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f" +
        "0e09a59ac083b0b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a" +
        "88688ef31d0bd9534ecaae3b84054dc5920852e918068dfd31f8c951bcf854d19d3f948" +
        "ff1dc362e5cbe65feffffff7f88b32b000000000401f9e31f000000000017005114aeff" +
        "40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005114fcc9a546f" +
        "cb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a4671" +
        "3fe8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874" +
        "393870b95028e5d31492679570b00")
        res = libnexa.get_txid(test_data)
        # the returned bytes are in little endian, txid is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e"
        return res_bytes.hex()

    def test_get_txidem(self):
        # random real transaction
        # https://explorer.nexa.org/tx/bf8cecf15389c83c9e1f902166435a557410046cbdc9fc07382a9cdebdd4844e
        test_data = bytes.fromhex("000100350b6a02bd95250365eb02799073d8c734817f" +
        "a93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f" +
        "0e09a59ac083b0b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a" +
        "88688ef31d0bd9534ecaae3b84054dc5920852e918068dfd31f8c951bcf854d19d3f948" +
        "ff1dc362e5cbe65feffffff7f88b32b000000000401f9e31f000000000017005114aeff" +
        "40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005114fcc9a546f" +
        "cb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a4671" +
        "3fe8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874" +
        "393870b95028e5d31492679570b00")
        res = libnexa.get_txidem(test_data)
        # the returned bytes are in little endian, txidem is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "0918083bc948fd652bbe506debac1e3dd531b792e3a4113351da9c911dd7b222"
        return res_bytes.hex()

    def test_hash_block_header(self):
        # random real block
        # https://explorer.nexa.org/block/225ba0029d19886988801c540821cdd7ba592d0f74f3076d914cdbdbbf4929e7
        test_data = bytes.fromhex("b0a68bf93c899741459f84d87dc398b1c6fedcde603aee4f9f4d93b0232" +
        "108fd00606b1af0fdbc690eb9ad00a5fd4efeddb91a3b3ca6bba3d7453920e511196faa4a516d416684da0" +
        "400d3971f705f83d3453aed66fb753bb8af38a72937c90656b0d4ab0000000000000000000000000000000" +
        "0000000000000000000000000000000000d1fc067acad7b1689085115cb573521000000000000000000000" +
        "00000000000000000000000001602000000000000020000001035440e4300004c00000000000012b9c6020" +
        "00002011dcb9a3b0000000017005114009b6557e49ced88ae43f460951314dc3cd7f8c0000000000000000" +
        "0000f6a037b570b0008000000000000000000000000000100350b6a02bd95250365eb02799073d8c734817" +
        "fa93961899139f9beea622952e36422210395c2b81c28f995f65bbb0b33edd80fe38e57f0e09a59ac083b0" +
        "b9362b2e8717240dd6a0f87cb80d37b24fd6f47b9d5d25d775c3a794a88688ef31d0bd9534ecaae3b84054" +
        "dc5920852e918068dfd31f8c951bcf854d19d3f948ff1dc362e5cbe65feffffff7f88b32b000000000401f" +
        "9e31f000000000017005114aeff40985d75fbcd2da1ecefe64618699e9cc42601572dd3010000000017005" +
        "114fcc9a546fcb518c72a68adb1cd0b06f3367532dc01895efb0b000000001700511441abf1d66a46713fe" +
        "8afc9d7a1d058d10ad2d6b7018917c51d000000001700511465f20faf7c480b1e874393870b95028e5d31492679570b00")
        res = libnexa.hash_block_header(test_data)
        # the returned bytes are in little endian, txidem is displayed in big endian, swap endian
        res_bytes = bytearray(res)
        res_bytes.reverse()
        res_bytes = bytes(res_bytes)
        # compare against explorer data
        assert res_bytes.hex() == "225ba0029d19886988801c540821cdd7ba592d0f74f3076d914cdbdbbf4929e7"
        return res_bytes.hex()

    def test_sign_tx_ecdsa(self):
        pass

    def test_sign_bch_tx_one_input_using_schnorr(self):
        pass

    def test_sign_tx_one_input_using_schnorr(self):
        tx_data = bytes.fromhex("0001002e203c16a4104613a60c3106f8dfb9b91542f0752cd6754302da44551b26c8a700ffffffff00e1f50500000000010038e0f505000000001976a9141f5dfc518bd18c2844e22975e58138bda9df8d4f88ac00000000")
        input_index = 0
        input_amount = 100000000
        script_pubkey = bytes.fromhex("76a914ceedd4ef1ea3f69b29f7cbf9f7e1b76378fe9c9f88ac")
        key = bytes.fromhex("3d8223f5cba7e6815e10bf250d61bb9e259b1c1f3f5fe2b16f4b79177083d282")
        sig_hash_type = 0
        sig = libnexa.sign_tx_one_input_using_schnorr(tx_data, input_index, input_amount, script_pubkey, sig_hash_type, key)
        assert sig == bytes.fromhex("b2facec4090be661e019726fb45b60b646de89c026c875372d621c90ac7a182b71b7189007dd7ac4ed901cc392e57556a67c8a2ec056fcca7cbaf7fe2881bdf2")
        return sig

    def test_sign_hash_schnorr(self):
        privkey = bytes.fromhex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
        hash = bytes.fromhex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")
        sig = libnexa.sign_hash_schnorr(hash, privkey)
        assert sig == bytes.fromhex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d0717571846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce")
        return sig

    def test_sign_hash_schnorr_with_nonce(self):
        privkey = bytes.fromhex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
        hash = bytes.fromhex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a")
        nonce = bytes.fromhex("6b0c7b03bd0576678cfdf5fa56d9a7165fe6a0097a673c15d1ada69cda6fcb35")
        sig = libnexa.sign_hash_schnorr_with_nonce(hash, privkey, nonce)
        assert sig == bytes.fromhex("fd3c6681c1540d5a7993bcf00114688dd897501a6d36cbac1bb6a2914cfb8bcf22d3b0b437d5f09b219b51dab75af5f27069b78f3dbae04239ea51ecce407927")
        return sig

    def test_parse_group_description(self):
        op_return_script = bytes.fromhex("6a0438564c0504415641530a417661277320436173681b68747470733a2f2f617661732e636173682f617661732e6a736f6e20780af03039b3c129374cb6cd133107ac5371a4bd659c22a93730e2495c227aaa58")
        res = libnexa.parse_group_description(op_return_script)
        op_return = res.decode("UTF-8")
        op_return = op_return[:-1] # remove trailing \n to make valid json object
        op_return = json.loads(op_return)
        expected_result = json.loads('{"ticker":"AVAS","name":"Ava\'s Cash","url":"https://avas.cash/avas.json","hash":"aa7a225c49e23037a9229c65bda47153ac073113cdb64c3729c1b33930f00a78","decimals":"8"}')
        assert op_return == expected_result
        return op_return

    def test_get_args_hash_from_script_pubkey(self):
        template = bytes.fromhex("005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        res = libnexa.get_args_hash_from_script_pubkey(template)
        args_hash = res.hex()
        assert args_hash == "b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return args_hash

    def test_get_template_hash_from_script_pubkey(self):
        pass

    def test_get_group_info_from_script_pubkey(self):
        pass

    def test_sign_message(self):
        msg = "this is a test msg".encode(encoding="UTF-8")
        privkey = bytes.fromhex("1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4")
        res = libnexa.sign_message(privkey, msg)
        sig = res.hex()
        assert sig == "2053a42ef1f7429b42e4b8676d8d6ce6fce716b43b2fa8580711822a7cff6aa83d492792db46cd79d39ccfae43a314473674e16153a277d2d1aaf0ba6014ca3df5"
        return sig

    def test_verify_message(self):
        pubkey = bytes.fromhex("03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea")
        pubkey_hash160 = libnexa.hash160(pubkey)
        msg = "this is a test msg".encode(encoding="UTF-8")
        sig = bytes.fromhex("2053a42ef1f7429b42e4b8676d8d6ce6fce716b43b2fa8580711822a7cff6aa83d492792db46cd79d39ccfae43a314473674e16153a277d2d1aaf0ba6014ca3df5")
        res = libnexa.verify_message(pubkey_hash160, msg, sig)
        assert res == True
        return res

    def test_recover_pubkey_from_signature(self):
        msg = "this is a test msg".encode(encoding="UTF-8")
        sig = bytes.fromhex("2053a42ef1f7429b42e4b8676d8d6ce6fce716b43b2fa8580711822a7cff6aa83d492792db46cd79d39ccfae43a314473674e16153a277d2d1aaf0ba6014ca3df5")
        res = libnexa.recover_pubkey_from_signature(msg, sig)
        found_pubkey = res.hex()
        assert found_pubkey == "03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea"
        return found_pubkey

    def test_verify_block_header(self):
        # random real mainnet block header 745745
        block_header = bytes.fromhex("3a048aa4e23d9f1e81f7d9e3dcd5dd9a137fb5b5eb9cbdd9cf3319e576b23bff4084761a2f6dedb66931b04894a00532d29cf001a0ed311093bd094e659beadf916d93e6de2fd38830dff43c2e39fb7a7abed4d15a071f1284d4c39a6f419fe54eb311040000000000000000000000000000000000000000000000000000000000000000ecfcc467acc111f3d2f1792fd7014b210000000000000000000000000000000000000000000000f90000000000000001000000102d94e7630000010000000000001322dd")
        res = libnexa.verify_block_header(1, block_header)
        assert res == True
        return res

    def test_encode_cash_addr(self):
        chain = 3
        type = 19
        data = bytes.fromhex("17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd")
        res = libnexa.encode_cash_addr(chain, type, data)
        addr = res.decode("utf-8")
        #print(addr)
        #print(type(addr))
        assert addr == "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        return addr

    def test_decode_cash_addr(self):
        chain = 3
        data = "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        type, res = libnexa.decode_cash_addr(chain, data)
        assert type == 19
        assert res.hex() == "17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return type, res.hex()

    def test_decode_cash_addr_content(self):
        chain = 3
        data = "nexareg:nqtsq5g5hp7zcsxqrvrzct0y9z0a7fmk440r4kxd22km289p"
        type, res = libnexa.decode_cash_addr_content(chain, data)
        assert type == 19
        assert res.hex() == "17005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return type, res.hex()

    def test_serialise_script(self):
        script = bytes.fromhex("005114e426dcecf04bb25eb6d5394017fe29cc62ccc325")
        res = libnexa.serialise_script(script)
        assert res.hex() == "17005114e426dcecf04bb25eb6d5394017fe29cc62ccc325"
        return res.hex()

    def test_pubkey_to_script_template(self):
        pubkey = bytes.fromhex("03be3bae13f4a4b11c9fbcaf3a7f9d85bec9e20b6d59ab087aae0f17e2856703ea")
        res = libnexa.pubkey_to_script_template(pubkey)
        assert res.hex() == "005114b87c2c40c01b062c2de4289fdf2776ad5e3ad8cd"
        return res.hex()

    def test_group_id_from_addr(self):
        # real mainnet token avas cash
        # expected id taken from rostrum output on explorer
        # https://explorer.nexa.org/token/nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x
        chain = 1
        addr = "nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x".encode(encoding="UTF-8")
        res = libnexa.group_id_from_addr(chain, addr)
        token_id_hex = res.hex()
        assert token_id_hex == "57f46c1766dc0087b207acde1b3372e9f90b18c7e67242657344dcd2af660000"
        return token_id_hex

    def test_group_id_to_addr(self):
        # real mainnet token avas cash
        # expected id taken from rostrum output on explorer
        # https://explorer.nexa.org/token/nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x
        chain = 1
        group_id = bytes.fromhex("57f46c1766dc0087b207acde1b3372e9f90b18c7e67242657344dcd2af660000")
        res = libnexa.group_id_to_addr(chain, group_id)
        addr = res.decode("UTF-8")
        assert addr == "nexa:tptlgmqhvmwqppajq7kduxenwt5ljzcccln8ysn9wdzde540vcqqqcra40x0x"
        return addr

    def test_decode_wif_private_key(self):
        chain = 3
        privkey = "cNaZtFp6sXP9obVngKwE5VpxJvZnua4XNorDpAfHaqUJ4KHXFZJ6".encode(encoding="UTF-8")
        res = libnexa.decode_wif_private_key(chain, privkey)
        privkey = res.hex()
        assert privkey == "1dc4be88ae449104b64dccb5aac2088dbd1fa65e20b46a63bae68f417bfcb5d4"
        return privkey

    def test_sha256(self):
        test_data = "SHA256 is considered to be safe".encode(encoding="UTF-8")
        res = libnexa.sha256(test_data)
        # check against expected
        assert res.hex() == "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630"
        # compare to python crypto
        assert res.hex() == util.sha256(test_data).hex()

    def test_hash256(self):
        test_data = "double SHA256 is considered to be safe".encode(encoding="UTF-8")
        res = libnexa.hash256(test_data)
        # check against expected
        assert res.hex() == "63e29a9e5de55b651a3592949cb389c92ff1c655d77e72b8dcd76c5579114067"
        # compare to python crypto
        assert res.hex() == util.hash256(test_data).hex()

    def test_hash160(self):
        test_data = "hash160 is used for addresses".encode(encoding="UTF-8")
        res = libnexa.hash160(test_data)
        # check against expected
        assert res.hex() == "900d6dd23c74f11cadfa1f519dff6be8d9d13fcd"
        # compare to python crypto
        assert res.hex() == util.hash160(test_data).hex()

    def test_get_work_from_difficulty_bits(self):
        bits = int("0x1b00954a", 16)
        res = libnexa.get_work_from_difficulty_bits(bits)
        work_bytes = res.hex()
        assert work_bytes == "0000000000000000000000000000000000000000000000000001b6fcbe9c2e23"
        return work_bytes

    def test_get_difficulty_bits_from_work(self):
        work_bytes = bytes.fromhex("232e9cbefcb60100000000000000000000000000000000000000000000000000")
        res = libnexa.get_difficulty_bits_from_work(work_bytes)
        difficulty = res
        assert difficulty == 453023050
        return difficulty

    def test_create_bloom_filter(self):
        pass

    def test_extract_from_merkle_block(self):
        pass

    def test_capd_solve(self):
        pass

    def test_capd_check(self):
        pass

    def test_capd_hash(self):
        pass

    def test_capd_set_pow_target_harder_than_priority(self):
        pass

    def test_crypt_aes_256_cbc(self):
        encrypt = 1
        msg = "We're blown. Run".encode(encoding="UTF-8")
        key = bytes.fromhex("3d8223f5cba7e6815e10bf250d61bb9e259b1c1f3f5fe2b16f4b79177083d282")
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        encrypted_bytes = libnexa.crypt_aes_256_cbc(encrypt, msg, key, iv)
        assert encrypted_bytes == bytes.fromhex("90bf29d1dee430a0a8fdbf6479431509")
        # now decrypt
        encrypt = 0
        decrypted_bytes = libnexa.cryptAES256CBC(encrypt, encrypted_bytes, key, iv)
        assert decrypted_bytes == msg
        return encrypted_bytes, decrypted_bytes

    def test_verify_data_schnorr(self):
        msg = "Very secret message 0: 11".encode(encoding="UTF-8")
        pubkey = bytes.fromhex("040B4C866585DD868A9D62348A9CD008D6A312937048FFF31670E7E920CFC7A7447B5F0BBA9E01E6FE4735C8383E6E7A3347A0FD72381B8F797A19F694054E5A69")
        sig = bytes.fromhex("B6E0D8588BFDFE8B29F4CDF87621BFEF9C2B4258B5AF765C61957392B017739F3881FE4ABB0FDC8ADF766E1D8476A23D4FF191EDF54578FC2D1117DC72FE0375")
        res = libnexa.verify_data_schnorr(msg, pubkey, sig)
        assert res == True
        return res

    def test_verify_hash_schnorr(self):
        hash = bytes.fromhex("b4f57530dbbf61c572d2eba40cac9819a70613c0b609526e3283dd5f4a5a46a4")
        pubkey = bytes.fromhex("040B4C866585DD868A9D62348A9CD008D6A312937048FFF31670E7E920CFC7A7447B5F0BBA9E01E6FE4735C8383E6E7A3347A0FD72381B8F797A19F694054E5A69")
        sig = bytes.fromhex("B6E0D8588BFDFE8B29F4CDF87621BFEF9C2B4258B5AF765C61957392B017739F3881FE4ABB0FDC8ADF766E1D8476A23D4FF191EDF54578FC2D1117DC72FE0375")
        res = libnexa.verify_hash_schnorr(hash, pubkey, sig)
        assert res == True
        return res

    def test_random_bytes(self):
        num_bytes = 32
        res = libnexa.random_bytes(num_bytes)
        assert len(res) == num_bytes
        random_bytes = res
        # check that the bytes are not the same 0 initalised array that
        # was made with create_string_buffer
        assert random_bytes != b"0000000000000000000000000000000000000000000000000000000000000000"
        res = libnexa.random_bytes(num_bytes)
        assert len(res) == num_bytes
        random_bytes2 = res
        assert random_bytes2 != b"0000000000000000000000000000000000000000000000000000000000000000"
        assert random_bytes != random_bytes2

    # end v2 tests

    # test compatability for all functions in v2 that are drop in replacements
    def test_drop_in_replacements(self):
        # lots of functions, easlier to list the ones that are not drop in replacements:
        # random_bytes - only because random bytes are random
        # verify message - v1 and v2 function differently, v1 was broken up into multiple apis in v2

        # Note: hash160, hash256, sha256 were removed from API v1 and are therefore not included in this test

        # except for version, api listed in lexicographical order
        # tests assert v1  == v2
        assert self.test_libnexaVersion() == self.test_libnexa_version()
        assert self.test_Bin2Hex() == self.test_bin_to_hex()
        assert self.test_capdCheck() == self.test_capd_check()
        assert self.test_capdHash() == self.test_capd_hash()
        assert self.test_capdSetPowTargetHarderThanPriority() == self.test_capd_set_pow_target_harder_than_priority()
        assert self.test_capdSolve() == self.test_capd_solve()
        assert self.test_createBloomFilter() == self.test_create_bloom_filter()
        assert self.test_cryptAES256CBC() == self.test_crypt_aes_256_cbc()
        assert self.test_decode64() == self.test_decode_base64()
        assert self.test_decodeCashAddr() == self.test_decode_cash_addr()
        assert self.test_decodeCashAddrContent() == self.test_decode_cash_addr_content()
        assert self.test_decodeWifPrivateKey() == self.test_decode_wif_private_key()
        assert self.test_encode64() == self.test_encode_base64()
        assert self.test_encodeCashAddr() == self.test_encode_cash_addr()
        assert self.test_extractFromMerkleBlock() == self.test_extract_from_merkle_block()
        assert self.test_getArgsHashFromScriptPubkey() == self.test_get_args_hash_from_script_pubkey()
        assert self.test_getDifficultyBitsFromWork() == self.test_get_difficulty_bits_from_work()
        assert self.test_getGroupTokenInfoFromScriptPubkey() == self.test_get_group_info_from_script_pubkey()
        assert self.test_GetPubKey() == self.test_get_pubkey()
        assert self.test_getTemplateHashFromScriptPubkey() == self.test_get_template_hash_from_script_pubkey()
        assert self.test_txid() == self.test_get_txid()
        assert self.test_txidem() == self.test_get_txidem()
        assert self.test_getWorkFromDifficultyBits() == self.test_get_work_from_difficulty_bits()
        assert self.test_groupIdFromAddr() == self.test_group_id_from_addr()
        assert self.test_groupIdToAddr() == self.test_group_id_to_addr()
        assert self.test_blockHash() == self.test_hash_block_header()
        assert self.test_hd44DeriveChildKey() == self.test_hd44_derive_child_key()
        assert self.test_parseGroupDescription() == self.test_parse_group_description()
        assert self.test_pubkeyToScriptTemplate() == self.test_pubkey_to_script_template()
        assert self.test_serializeScript() == self.test_serialise_script()
        assert self.test_signBchTxOneInputUsingSchnorr() == self.test_sign_bch_tx_one_input_using_schnorr()
        assert self.test_SignHashEDCSA() == self.test_sign_hash_ecdsa()
        assert self.test_signHashSchnorr() == self.test_sign_hash_schnorr()
        assert self.test_signHashSchnorrWithNonce() == self.test_sign_hash_schnorr_with_nonce()
        assert self.test_signMessage() == self.test_sign_message()
        assert self.test_SignTxECDSA() == self.test_sign_tx_ecdsa()
        assert self.test_signTxOneInputUsingSchnorr() == self.test_sign_tx_one_input_using_schnorr()
        assert self.test_verifyBlockHeader() == self.test_verify_block_header()
        assert self.test_verifyDataSchnorr() == self.test_verify_data_schnorr()
        assert self.test_verifyHashSchnorr() == self.test_verify_hash_schnorr()



    def run_test(self):
        libnexa_methods = libnexa_test_coverage.get_libnexa_api_methods()
        libnexa_tested_methods = [func for func in dir(LibnexaTest) if callable(getattr(LibnexaTest, func)) and not func.startswith("__")]
        for method in libnexa_methods:
            test_method_name = "test_" + method
            if test_method_name not in libnexa_tested_methods:
                print(test_method_name)
            assert test_method_name in libnexa_tested_methods

        assert libnexa_test_coverage.test_api_wrapper_arg_res_types(libnexa_methods) == True

        # v1 tests
        self.test_libnexaVersion()
        self.test_encode64()
        self.test_decode64()
        self.test_Bin2Hex()
        self.test_hd44DeriveChildKey()
        #self.test_SignHashEDCSA() # BCH API, omitted from test
        self.test_GetPubKey()
        self.test_txid()
        self.test_txidem()
        self.test_blockHash()
        #self.test_SignTxECDSA() # BCH API, omitted from test
        #self.test_signBchTxOneInputUsingSchnorr() # BCH API, omitted from test
        self.test_signTxOneInputUsingSchnorr()
        self.test_SignTxSchnorr()
        self.test_signHashSchnorr()
        self.test_signHashSchnorrWithNonce()
        self.test_parseGroupDescription()
        self.test_getArgsHashFromScriptPubkey()
        self.test_getTemplateHashFromScriptPubkey()
        self.test_getGroupTokenInfoFromScriptPubkey()
        self.test_signMessage()
        self.test_verifyMessage()
        self.test_verifyBlockHeader()
        self.test_encodeCashAddr()
        self.test_decodeCashAddr()
        self.test_decodeCashAddrContent()
        self.test_serializeScript()
        self.test_pubkeyToScriptTemplate()
        self.test_groupIdFromAddr()
        self.test_groupIdToAddr()
        self.test_decodeWifPrivateKey()
        self.test_sha256()
        self.test_hash256()
        self.test_hash160()
        self.test_getWorkFromDifficultyBits()
        self.test_getDifficultyBitsFromWork()
        #self.test_createBloomFilter()
        #self.test_extractFromMerkleBlock()
        #self.test_capdSolve()
        #self.test_capdCheck()
        #self.test_capdHash()
        #self.test_capdSetPowTargetHarderThanPriority()
        self.test_cryptAES256CBC()
        self.test_verifyDataSchnorr()
        self.test_verifyHashSchnorr()
        self.test_RandomBytes()

        #v2 tests
        self.test_libnexa_version()
        self.test_get_libnexa_error()
        self.test_get_libnexa_error_string()

        self.test_bin_to_hex()
        #self.test_capd_check()
        #self.test_capd_hash()
        #self.test_capd_set_pow_target_harder_than_priority()
        #self.test_capd_solve()
        #self.test_create_bloom_filter()
        self.test_crypt_aes_256_cbc()
        self.test_decode_base64()
        self.test_decode_cash_addr()
        self.test_decode_cash_addr_content()
        self.test_decode_wif_private_key()
        self.test_encode_base64()
        self.test_encode_cash_addr()
        self.test_extract_from_merkle_block()
        self.test_get_args_hash_from_script_pubkey()
        self.test_get_difficulty_bits_from_work()
        self.test_get_group_info_from_script_pubkey()
        self.test_get_pubkey()
        self.test_get_template_hash_from_script_pubkey()
        self.test_get_txid()
        self.test_get_txidem()
        self.test_get_work_from_difficulty_bits()
        self.test_group_id_from_addr()
        self.test_group_id_to_addr()
        self.test_hash160()
        self.test_hash256()
        self.test_hash_block_header()
        self.test_hd44_derive_child_key()
        self.test_parse_group_description()
        self.test_pubkey_to_script_template()
        self.test_random_bytes()
        self.test_recover_pubkey_from_signature()
        self.test_serialise_script()
        self.test_sha256()
        #self.test_sign_bch_tx_one_input_using_schnorr()
        #self.test_sign_hash_ecdsa()
        self.test_sign_hash_schnorr()
        self.test_sign_hash_schnorr_with_nonce()
        self.test_sign_message()
        #self.test_sign_tx_ecdsa()
        self.test_sign_tx_one_input_using_schnorr()
        self.test_verify_block_header()
        self.test_verify_data_schnorr()
        self.test_verify_hash_schnorr()
        self.test_verify_message()

        # drop in replacement tests
        self.test_drop_in_replacements()

if __name__ == '__main__':
    LibnexaTest().main()

# Create a convenient function for an interactive python debugging session


def Test():
    t = LibnexaTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    #import signal, pdb
    #signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags() # ["--nocleanup", "--noshutdown"]
    binpath = findBitcoind()
    flags.append("--srcdir=%s" % binpath)
    t.main(flags, bitcoinConf, None)
