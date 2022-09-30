// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "test_main.h"
#include "test/test_nexa.h"

static const CKeyID keyid1 = CKeyID(uint160(ParseHex("816115944e077fe7c803cfa57f29b36bf87c1d35")));

static uint256 uint256S_keep_endian(const char *psz)
{
    uint256_t res;
    std::memcpy(res, UINT256_ZERO, UINT256_NUM_BYTES);
    // hex string to uint
    uint8_t *p1 = (uint8_t*)res;
    uint8_t *pend = p1 + 32;
    size_t digits = 0;
    while (digits < 64 && p1 < pend)
    {
        uint8_t nibble1 = (uint8_t)::HexDigit(psz[digits++]);
        uint8_t nibble2 = (uint8_t)::HexDigit(psz[digits++]);
        *p1 = nibble1 << 4;
        *p1 |= (nibble2 & 0x0f);
        p1++;
    }
    return uint256(res);
}

void test_fingerprint_add(CCoinsViewDB *coindb_cashdrive, std::string outpoint_hash)
{
    COutPoint outpoint;
    // uint256S will change the endianness, use this workaround instead
    outpoint.hash = uint256S_keep_endian(outpoint_hash.c_str());
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    int64_t amount = 10;
    CTxOut out(amount, script1);
    Coin coin(out, 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
}

void test_fingerprint_spend(CCoinsViewDB *coindb_cashdrive, std::string outpoint_hash)
{
    COutPoint outpoint;
    outpoint.hash = uint256S_keep_endian(outpoint_hash.c_str());
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
}

// 0000000000000000000000000000000000000000000000000000000000000000

// left side
// 19 = 9ad962084a1ef50328321beda15af65419fbd3eaa2dc5403146e50fdd79fa79f

// 1d = a733006c55a59e7fb3d66ed9ea18cb0408f3203aec19cc54090e9c5a6a96c37e

// 15 = f3a355480d1c3c29a86955593ca40c4f93346db74c9d07f97ba44f0d2e344109

// 0f = f32f72503ad41d87caae7f0bf4010bd76ee308faffe478ea4bbf0f5a617bedcb

// 09 = da5788c597ec6fe857aa0e3e5925f12c28fa5e0fc4fecfcfe7c3c31b481849b7

// 07 = ff4075aff4bbe30c93cbc033b6aa6777b4501bf4e68cac6d3f1ecf0103e28966

// 13 = dcaeb83797a97fc97f3623cc566c6b68f37150e00c16688ce2bdb705fe89679b




// right side

// 1b = 5f80b9a29ea0adda1b5e5d82db06b286a409c4e89a2707a824734f152931e0cb

// 11 = 3df8b82bb22d5cf85351c8ff9e7131452cbf58fb577aefec01e3de4e8cbaa2da

// 0b = 7e3024b8464a546e5f4aa86f45ec4d650c92ea5a5e6beb375a1ad86577c3bbf1

// 17 = 4552e2c74b13cd0f1b3c1fe6bbb8e9a3c95f57ef22fddd14358c646ffff0f706

// 0d = a753de9143f6af0b08b68dc3856c341a7ed44493bb6d9842a45c8953d05d478c

// 05 = 615358032dc9339b301f93d51c8b6c6841cae06447cabb55fbd428c960bb2f16


// root = 7124bd808b1f83ec040d4c601468a613fd663d40e1c7fc73450c19de63d63ff3

// test the fingerprint against the expected fingerprint of the nexa chain as of block 15
void test_fingerprint(CCoinsViewDB *coindb_cashdrive)
{
    // add the outpoints from the first 15 blocks in no particular order with fake coin values
    test_fingerprint_add(coindb_cashdrive, "0bce6204dd548d7ebd3a21f4fad0f949d716230b5a3f069e342eeb62f252ef8d");

    uint256 expected_fingerprint = uint256S_keep_endian("4f14392498956303fbd2fc8e4a9ff57f25e0d6d3ceedcf0678f4fb789416813f");
    uint256 result_fingerprint = coindb_cashdrive->GetFingerprint();
    assert(result_fingerprint == expected_fingerprint);

    test_fingerprint_add(coindb_cashdrive, "399c4b87dd82b0a9837815ad67da1d527b0a49bec95459198fd53ddae1197d16");

    result_fingerprint = coindb_cashdrive->GetFingerprint();
    expected_fingerprint = uint256S_keep_endian("e86c45f5b63ce4d548f7a2aa0c53f0e4f02d5f2e716f922942ff367de260b929");
    assert(result_fingerprint == expected_fingerprint);

    test_fingerprint_add(coindb_cashdrive, "47ecef8aff3e35e34274445147943c5e61664a9f729d76775da645010b60bbe3");
    test_fingerprint_add(coindb_cashdrive, "4f8ef884b4e438a7c7e433a6b57bfbe813133654cd817699fc4f49d3ef07ee8e");
    test_fingerprint_add(coindb_cashdrive, "5880784329bb383058109bb769bfb8a01fc33cc8432136ae07ed83a5ec3f3d1a");
    test_fingerprint_add(coindb_cashdrive, "69df7e7f2f86b97680aca6cb450a134415b8960bc731eb22603992816fbbb91a");
    test_fingerprint_add(coindb_cashdrive, "738aaabac6e473ce6d710ab4fb61c6c0a3697f01df945f023d4e46d52419f0ff");
    test_fingerprint_add(coindb_cashdrive, "78d8c44ecfeb10b529758c143556482090703af005d4a48e4306d43ed74c0ca0");
    test_fingerprint_add(coindb_cashdrive, "8419c991c83138679433433f54510751cdd7014e62c12c429f0dec26916931c3");
    test_fingerprint_add(coindb_cashdrive, "85cf04b7a7a9838fdd30edcc475139375a17b7623f5951ca068fe3d313b754c2");
    test_fingerprint_add(coindb_cashdrive, "a44d472f3fc29b76943a5c0cbf57562ffcf8853b777d50477bd75f72d5abce0d");
    test_fingerprint_add(coindb_cashdrive, "b29d1e493c346be0e1ca3da01a10b4251a1e4c5bf806f973e21037762593acb6");
    test_fingerprint_add(coindb_cashdrive, "b2b9bbfbc6a3e83b521c3482447f6bd70b5bfda35373c0f62eecb7f4a0a1ee1d");
    test_fingerprint_add(coindb_cashdrive, "b8e3bb7aa842f754b233b52fd0f3394b00e461c68bceabf233e6d2fb84a10c64");
    test_fingerprint_add(coindb_cashdrive, "eb79f4de002fe6e37260e24d053d085d7813903c0c07d565304a03a6ab2d6789");

    result_fingerprint = coindb_cashdrive->GetFingerprint();
    expected_fingerprint = uint256S_keep_endian("7124bd808b1f83ec040d4c601468a613fd663d40e1c7fc73450c19de63d63ff3");
    assert(result_fingerprint == expected_fingerprint);

    printf("add fingerprint test passed \n");

    // TODO: sprinkle a couple of asserts in the spends to check that the fingerprint is still what is expected

    // clean up by spending everything that was added
    test_fingerprint_spend(coindb_cashdrive, "0bce6204dd548d7ebd3a21f4fad0f949d716230b5a3f069e342eeb62f252ef8d");
    test_fingerprint_spend(coindb_cashdrive, "399c4b87dd82b0a9837815ad67da1d527b0a49bec95459198fd53ddae1197d16");
    test_fingerprint_spend(coindb_cashdrive, "47ecef8aff3e35e34274445147943c5e61664a9f729d76775da645010b60bbe3");
    test_fingerprint_spend(coindb_cashdrive, "4f8ef884b4e438a7c7e433a6b57bfbe813133654cd817699fc4f49d3ef07ee8e");
    test_fingerprint_spend(coindb_cashdrive, "5880784329bb383058109bb769bfb8a01fc33cc8432136ae07ed83a5ec3f3d1a");
    test_fingerprint_spend(coindb_cashdrive, "69df7e7f2f86b97680aca6cb450a134415b8960bc731eb22603992816fbbb91a");
    test_fingerprint_spend(coindb_cashdrive, "738aaabac6e473ce6d710ab4fb61c6c0a3697f01df945f023d4e46d52419f0ff");
    test_fingerprint_spend(coindb_cashdrive, "78d8c44ecfeb10b529758c143556482090703af005d4a48e4306d43ed74c0ca0");
    test_fingerprint_spend(coindb_cashdrive, "8419c991c83138679433433f54510751cdd7014e62c12c429f0dec26916931c3");
    test_fingerprint_spend(coindb_cashdrive, "85cf04b7a7a9838fdd30edcc475139375a17b7623f5951ca068fe3d313b754c2");
    test_fingerprint_spend(coindb_cashdrive, "a44d472f3fc29b76943a5c0cbf57562ffcf8853b777d50477bd75f72d5abce0d");
    test_fingerprint_spend(coindb_cashdrive, "b29d1e493c346be0e1ca3da01a10b4251a1e4c5bf806f973e21037762593acb6");
    test_fingerprint_spend(coindb_cashdrive, "b2b9bbfbc6a3e83b521c3482447f6bd70b5bfda35373c0f62eecb7f4a0a1ee1d");
    test_fingerprint_spend(coindb_cashdrive, "b8e3bb7aa842f754b233b52fd0f3394b00e461c68bceabf233e6d2fb84a10c64");
    test_fingerprint_spend(coindb_cashdrive, "eb79f4de002fe6e37260e24d053d085d7813903c0c07d565304a03a6ab2d6789");

    // all nodes should be spent, assert right and left of root are both NULL
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Fingerprint test passed \n");

    // fingerprint for empty trie check
    result_fingerprint = coindb_cashdrive->GetFingerprint();
    expected_fingerprint = uint256S_keep_endian("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    assert(result_fingerprint == expected_fingerprint);
}
