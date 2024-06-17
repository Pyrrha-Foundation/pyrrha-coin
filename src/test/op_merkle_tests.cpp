// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/merkle.h"
#include "core_io.h"
#include "test/test_nexa.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <iostream>
#include <fstream>

template <unsigned int BITS>
std::string hex(base_blob<BITS> blob) {
    blob.reverse();
    return blob.GetHex();
}

BOOST_FIXTURE_TEST_SUITE(op_merkle_tests, BasicTestingSetup)

// call signature: <ROOT> <proof0proof1proofN> <leafIndex> <leaf> <algoIndex> OP_MERKLE
BOOST_AUTO_TEST_CASE(validations_test) {
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis; // no imported state
    ScriptError error;
    bool ret;

    // fail, invalid amount of arguments (0)
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // fail, invalid amount of arguments (1)
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // fail, invalid amount of arguments (2)
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // fail, invalid amount of arguments (3)
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          OP_1 << ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // ok, valid amount of arguments (4), negative result
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("14253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE <<
          ParseHex("d008eb3373fe5dc992bd2c2dfe40cc7181ba29cd") << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EQUALVERIFY);
    }

    // fail, unknown algo index
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("14253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_10 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_NUMBER_RANGE);
    }

    // fail, negative leaf index
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("14253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1NEGATE <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
    }

    // fail, leaf size 0
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("14253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1 <<
          ParseHex("") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_OPERAND_SIZE);
    }

    // fail, leaf size not multiple of hash size
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("14253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1 <<
          ParseHex("beef") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_OPERAND_SIZE);
    }

    // fail, proof size 0
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("") << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_OPERAND_SIZE);
    }

    // fail, proof element size not 160 bit
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("02beef") << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_OPERAND_SIZE);
    }

    // fail, serialized proof is not pushonly contains an opcode
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex("6a253dd43e0a12ebcc6cd6bb76289460a61d512a06") << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_BAD_OPERATION_ON_TYPE);
    }
}

BOOST_AUTO_TEST_CASE(hash160_test) {
    std::vector<uint160> leaves = {
      uint160(ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b")),
      uint160(ParseHex("253dd43e0a12ebcc6cd6bb76289460a61d512a06")),
      uint160(ParseHex("d008eb3373fe5dc992bd2c2dfe40cc7181ba29cd")),
      uint160(ParseHex("2f3cd334f5a0ca4dd4df63e6c2a643caa9ee9319")),
      uint160(ParseHex("e911d82a812dcc1537fde9fffba63b459d2bf0ad")),
      uint160(ParseHex("f312fc8bd00b1e436c3f7c59a4ac63c59aa5b356")),
      uint160(ParseHex("77e62946f860e19dbc58408b40a854beef6ee73a")),
      uint160(ParseHex("28c2fa25b051f0d9d3fda564081090e2d5af1ed2")),
      uint160(ParseHex("62166629f731321447de81bf5581838a59d34409")),
      uint160(ParseHex("d65ce313f715833dfb9bcbe04aa28d6c2e67bd11")),
      uint160(ParseHex("5e964d9bf85156c9b727da01340cb91e3e8672a5")),
      uint160(ParseHex("b0ce218cf6df40b49599ce48236ac0c20f9ba4a3")),
      uint160(ParseHex("068c7b2391c29bf12217740478b3117b01191c08")),
      uint160(ParseHex("a3fcfef1e79294dcf6bf4ee4edacf4f608bc30e4")),
      uint160(ParseHex("3f0c508ed723a34238550f0cbce609ab59e9ab31")),
      uint160(ParseHex("fb47813521c6e9a4f9c7d8e0c0c49de6ab7d6e25")),
      uint160(ParseHex("0000000000000000000000000000000000000000")),
    };

    std::vector<uint160> mklProof = MerkleHash160::ComputeMerkleBranch(leaves, 0);
    std::string proof = "";
    for (const auto& element : mklProof) {
        proof += "14" + hex(element);
    }

    uint160 root = MerkleHash160::ComputeMerkleRootFromBranch(leaves[0], mklProof, 0);


    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis; // no imported state
    ScriptError error;
    bool ret;

    // ok, valid merkle proof
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_0 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // fail, wrong merkle proof for element at index 1
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_1 <<
          ParseHex("f833e698fb72f2e6a096dca1c0a6d4ac6930b37b") << OP_1 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EQUALVERIFY);
    }

    // get compact proof for 17th element in the tree
    mklProof = MerkleHash160::ToCompactProof(MerkleHash160::ComputeMerkleBranch(leaves, 16), 16);
    BOOST_CHECK(mklProof.size() == 1);
    proof = "";
    for (const auto& element : mklProof) {
        proof += "14" + hex(element);
    }

    root = MerkleHash160::ComputeMerkleRootFromBranch(leaves[16], mklProof, 16);

    // ok, valid compact merkle proof
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_0 <<
          ParseHex("0000000000000000000000000000000000000000") << OP_1 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }
}

BOOST_AUTO_TEST_CASE(hash256_test) {
    std::vector<uint256> leaves = {
      uint256(ParseHex("c455341393a77a07669232bbb39d84eb80c9723c5a2a76118b6e48de818a922e")),
      uint256(ParseHex("86b99ad436c32bdeea145d94a4aa4f12d027bf13113e719043eb9d25659e8d6c")),
      uint256(ParseHex("50b690aaf38b7c89efc6d752d8b29ffe62e5178087ecf3f154a7d6ad6e61a6a7")),
      uint256(ParseHex("3e6b1ba1875bb9060a45d23afa06544eba2df41c2f0816fa9e2503fb48f7d845")),
      uint256(ParseHex("9b7118990d64ecf083dcc634b03b558f7d687a809599830b606208dda9de3f27")),
      uint256(ParseHex("8784fbb270a3cf9f1d0ef987660f626c489f086b5e6092e62e034880cb24000f")),
      uint256(ParseHex("01b9b4f6153dcd07cceb27f1db442a5b0bb95287e1fa3bc3c5f0fe512f16ebd2")),
      uint256(ParseHex("3e6c42e4e080e24ed408a52354f973c0d52a34f32100481a59c0b241cf8285ec")),
      uint256(ParseHex("1858f2f40d7cd2f04fe3a94de41075575faf7e6367d9c15da357ba8ef93a6aad")),
      uint256(ParseHex("6c81358809eab5624c1fe4ba2a04b5b5d15de0675a8aafcb2cc5127df4f3bd50")),
      uint256(ParseHex("0588c169676a1ee0e90793eecffdbc863a49130359240997027daadaeb30d5d8")),
      uint256(ParseHex("ce839ebad90555b05e08cfa4c5b7f222fad5753f4cdbec97026a7c80f0718191")),
      uint256(ParseHex("5513abb4279473f81f7407c420bd63464c772de367872277ab4bbc80d1a64fbe")),
      uint256(ParseHex("318462e5a7404accdb9b28dc0a3dbca2baa69b475bfe7aac6fb42c4ccd6f7cbf")),
      uint256(ParseHex("201754330c34f188a46e27b61be81747e092a60762f29fc39d378adaf2ccb4c9")),
      uint256(ParseHex("56b015d4e588622c0b8f5737ca2089395f90d130fcd890769676ae7a23c9d1eb")),
      uint256(ParseHex("0000000000000000000000000000000000000000000000000000000000000000")),
    };

    std::vector<uint256> mklProof = MerkleHash256::ComputeMerkleBranch(leaves, 0);
    std::string proof = "";
    for (const auto& element : mklProof) {
        proof += "20" + hex(element);
    }

    uint256 root = MerkleHash256::ComputeMerkleRootFromBranch(leaves[0], mklProof, 0);


    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis; // no imported state
    ScriptError error;
    bool ret;

    // ok, valid merkle proof
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_0 <<
          ParseHex("c455341393a77a07669232bbb39d84eb80c9723c5a2a76118b6e48de818a922e") << OP_0 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // fail, wrong merkle proof for element at index 1
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_1 <<
          ParseHex("c455341393a77a07669232bbb39d84eb80c9723c5a2a76118b6e48de818a922e") << OP_0 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EQUALVERIFY);
    }

    // get compact proof for 17th element in the tree
    mklProof = MerkleHash256::ToCompactProof(MerkleHash256::ComputeMerkleBranch(leaves, 16), 16);
    BOOST_CHECK(mklProof.size() == 1);
    proof = "";
    for (const auto& element : mklProof) {
        proof += "20" + hex(element);
    }

    root = MerkleHash256::ComputeMerkleRootFromBranch(leaves[16], mklProof, 16);

    // ok, valid compact merkle proof
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_0 <<
          ParseHex("0000000000000000000000000000000000000000000000000000000000000000") << OP_0 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }
}

BOOST_AUTO_TEST_CASE(block_tx_proof_test) {
    std::ifstream blockData("src/test/data/block_391502.hex");
    std::string blockHex((std::istreambuf_iterator<char>(blockData)),
        (std::istreambuf_iterator<char>()));

    CBlock block;
    DecodeHexBlk(block, blockHex);
    const uint256 root = BlockMerkleRoot(block);
    BOOST_CHECK(root == block.hashMerkleRoot);
    const std::vector<uint256> blockMerkleBranch = BlockMerkleBranch(block, 0);
    std::string proof = "";
    for (const auto& element : blockMerkleBranch) {
        proof += "20" + hex(element);
    }

    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis; // no imported state
    ScriptError error;
    bool ret;

    // ok, valid merkle proof
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_0 <<
          ParseHex(hex(block.vtx[0]->GetId())) << OP_0 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // fail, wrong merkle proof for element at index 1
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          ParseHex(proof) << OP_1 <<
          ParseHex(hex(block.vtx[0]->GetId())) << OP_0 << OP_MERKLE <<
          ParseHex(hex(root)) << OP_EQUALVERIFY << OP_1;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_EQUALVERIFY);
    }
}

BOOST_AUTO_TEST_CASE(next_proof_test) {
    const std::vector<std::string> leaves = {
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk", "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt", "uu", "vv", "ww", "xx", "yy", "zz",
        "AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH", "II", "JJ", "KK", "LL", "MM", "NN", "OO", "PP", "QQ", "RR", "SS", "TT", "UU", "VV", "WW", "XX", "YY", "ZZ",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    };
    std::vector<uint160> hashes;
    std::transform(leaves.begin(), leaves.end(), std::back_inserter(hashes), [](const auto& item){
        return uint160(Hash160(item.begin(), item.end()));
    });

    std::vector<uint160> prevProof;
    std::vector<uint160> prevCompactProof;
    uint160 prevRoot;
    uint32_t prevIndex = 0;
    uint160 prevLeafHash = hashes[prevIndex];
    {
        const std::vector<uint160> copy(hashes.begin(), hashes.begin() + prevIndex + 1);

        std::vector<uint160> mklProof = MerkleHash160::ComputeMerkleBranch(copy, prevIndex);

        prevProof = mklProof;
        prevCompactProof = MerkleHash160::ToCompactProof(prevProof, prevIndex);

        prevRoot = MerkleHash160::ComputeMerkleRootFromBranch(copy[prevIndex], mklProof, prevIndex);
    }

    for (prevIndex = 0; prevIndex < 129; prevIndex++) {
        const auto newCompactProof = MerkleHash160::GetNewCompactProof(prevLeafHash, prevCompactProof, prevIndex);
        const uint32_t newIndex = prevIndex + 1;
        uint160 newRootFromFullProof;
        const auto newFullProof = MerkleHash160::ToFullProof(hashes[newIndex], newCompactProof, newIndex, &newRootFromFullProof);
        const uint160 newRoot = MerkleHash160::ComputeMerkleRootFromBranch(hashes[newIndex], newFullProof, newIndex);
        // verification
        {
            const std::vector<uint160> copy(hashes.begin(), hashes.begin() + newIndex + 1);

            std::vector<uint160> fullProof = MerkleHash160::ComputeMerkleBranch(copy, newIndex);
            BOOST_CHECK(fullProof == newFullProof);

            const uint160 root = MerkleHash160::ComputeMerkleRootFromBranch(copy[newIndex], fullProof, newIndex);
            BOOST_CHECK(newRoot == root);
            BOOST_CHECK(newRootFromFullProof == root);

            std::vector<uint160> compactProof = MerkleHash160::ToCompactProof(fullProof, newIndex);
            BOOST_CHECK(newCompactProof == compactProof);

            prevProof = newFullProof;
            prevCompactProof = newCompactProof;
            prevRoot = root;
            prevLeafHash = hashes[newIndex];
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
