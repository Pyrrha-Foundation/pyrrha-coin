// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

static const CKeyID keyid1 = CKeyID(uint160(ParseHex("816115944e077fe7c803cfa57f29b36bf87c1d35")));

static void _test_add_1(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    int64_t amount = 10;
    CTxOut out(amount, script1);
    Coin coin(out, 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    // should have added a node on the left, verify that it has added the correct node information
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 256);
    assert(std::memcmp(root_left.key, key, UINT256_NUM_BYTES) == 0);
    assert(root_left.value == coin);
    printf("Add-1 test passed \n");
}

static void _test_add_2(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {129,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    // should have added a node on the right, verify that it has added the correct node information
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 256);
    assert(std::memcmp(root_right.key, key, UINT256_NUM_BYTES) == 0);
    // verify the left has not changed, verify that it has added the correct node information
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 256);
    assert(root_left.key[0] == 127);
    printf("Add-2 test passed \n");
}

static void _test_add_3(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {131,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    // left should have remained untouched
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 256);
    assert(root_left.key[0] == 127);
    // right should now be an interior node, interior nodes do not have 256 key bits
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 6);
    // the right of the interior node should be the new added node
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(root_right_right.key_bits == 256);
    std::string str_key = uint256t_ToString(key);
    std::string str_new_key = uint256t_ToString(root_right_right.key);
    //assert(std::memcmp(root_right_right.key, key, UINT256_NUM_BYTES) == 0);
    // the interior left should be the old right node
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    std::string str_key2 = uint256t_ToString(root_right_left.key);
    assert(root_right_left.key_bits == 256);
    assert(root_right_left.key[0] == 129);
    printf("Add-3 test passed \n");
}

static void _test_add_4(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {130,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    // left should have remained untouched
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 256);
    assert(root_left.key[0] == 127);
    // right is still interior node
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 6);

    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(root_right_left.key_bits == 256);
    assert(root_right_left.key[0] == 129);

    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    // the number of bits in an interior must be more than the number of bits
    // in any interiors closer to the root than it
    assert(root_right_right.key_bits == 7);
    // right right right should be the new old right right
    const CoinEntryValue root_right_right_right = coindb_cashdrive->_GetValueByKey(root_right_right.key_right);
    assert(root_right_right_right.key_bits == 256);
    assert(root_right_right_right.key[0] == 131);
    // right right left should be the new node added this test
    const CoinEntryValue root_right_right_left = coindb_cashdrive->_GetValueByKey(root_right_right.key_left);
    assert(root_right_right_left.key_bits == 256);
    assert(std::memcmp(root_right_right_left.key, key, UINT256_NUM_BYTES) == 0);
    printf("Add-4 test passed \n");
}

static void _test_add_5(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {126,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    // added an intermeidate node on the left, moved old left to interior right
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 7);

    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 256);
    assert(root_left_right.key[0] == 127);
    // new node was added on root left left
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 256);
    assert(std::memcmp(root_left_left.key, key, UINT256_NUM_BYTES) == 0);
    printf("Add-5 test passed \n");
}

static void _test_add_6(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {124,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    // interior node at root left was replaced with one with less key bits because
    // a split was needed higher up and was put at the new left's, right. verify this
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    // old interior node had 7 key bits, new one is above it so it must have less
    assert(root_left.key_bits == 6);
    // old interior should be at left right
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key[0] == 126);
    assert(root_left_right.key_bits == 7);
    // and it should have the same children it did before it was moved
    const CoinEntryValue root_left_right_left = coindb_cashdrive->_GetValueByKey(root_left_right.key_left);
    assert(root_left_right_left.key_bits == 256);
    assert(root_left_right_left.key[0] == 126);

    const CoinEntryValue root_left_right_right = coindb_cashdrive->_GetValueByKey(root_left_right.key_right);
    assert(root_left_right_right.key_bits == 256);
    assert(root_left_right_right.key[0] == 127);
    // new node added in this test shoud be on root left left
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 256);
    assert(std::memcmp(root_left_left.key, key, UINT256_NUM_BYTES) == 0);
    printf("Add-6 test passed \n");
}

static void _test_add_7(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {125,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    /*
    // full trie validation, only showing key[0] for brevity
    // trie should have final shape of:
    //                     root = XXXXXXXX
    //                    /               \
    //               011111XX             100000XX
    //              /        |             /      |
    //       0111110X         011111X  10000001    1000001X
    //     /       |          /     |                 /    |
    // 01111100  01111101  01111110  01111111   10000010   10000011
    //
    */
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0);
    assert(root.key_bits == 0);
    // now check the right
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 6);
    assert(root_right.root_group == root.root_group);
    // the first leaf node is root right left
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(root_right_left.key_bits == 256);
    assert(root_right_left.key[0] == 129);
    assert(std::memcmp(root_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // go right
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(root_right_right.key_bits == 7);
    assert(root_right_right.root_group == root.root_group);
    // leaf node 10000010
    const CoinEntryValue root_right_right_left = coindb_cashdrive->_GetValueByKey(root_right_right.key_left);
    assert(root_right_right_left.key_bits == 256);
    assert(root_right_right_left.key[0] == 130);
    assert(std::memcmp(root_right_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // right side
    const CoinEntryValue root_right_right_right = coindb_cashdrive->_GetValueByKey(root_right_right.key_right);
    assert(root_right_right_right.key_bits == 256);
    assert(root_right_right_right.key[0] == 131);
    assert(std::memcmp(root_right_right_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_right_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // right side verified, verify the left
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 6);
    assert(root_left.root_group == root.root_group);

    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 7);
    assert(root_left_left.root_group == root.root_group);
    // the two leaf nodes on root left left

    const CoinEntryValue root_left_left_left = coindb_cashdrive->_GetValueByKey(root_left_left.key_left);
    assert(root_left_left_left.key_bits == 256);
    assert(root_left_left_left.key[0] == 124);
    assert(std::memcmp(root_left_left_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_left_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);

    const CoinEntryValue root_left_left_right = coindb_cashdrive->_GetValueByKey(root_left_left.key_right);
    assert(root_left_left_right.key[0] == 125);
    assert(root_left_left_right.key_bits == 256);
    assert(std::memcmp(root_left_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // go back to root left and go right
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 7);
    assert(root_left_right.root_group == root.root_group);
    // check the leaf nodes on root left right
    const CoinEntryValue root_left_right_left = coindb_cashdrive->_GetValueByKey(root_left_right.key_left);
    assert(root_left_right_left.key_bits == 256);
    assert(root_left_right_left.key[0] == 126);
    assert(std::memcmp(root_left_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);

    const CoinEntryValue root_left_right_right = coindb_cashdrive->_GetValueByKey(root_left_right.key_right);
    assert(root_left_right_right.key_bits == 256);
    assert(root_left_right_right.key[0] == 127);
    assert(std::memcmp(root_left_right_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);

    printf("Add-7 test passed \n");
}


static void _test_add_8(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {125,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    Coin coin(CTxOut(10, script1), 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == false);

    printf("Add-8 test passed \n");
}

void test_adds(CCoinsViewDB *coindb_cashdrive)
{
    // add left
    _test_add_1(coindb_cashdrive);
    // add right
    _test_add_2(coindb_cashdrive);
    // add right
    _test_add_3(coindb_cashdrive);
    // add right
    _test_add_4(coindb_cashdrive);
    // add left
    _test_add_5(coindb_cashdrive);
    // add left
    _test_add_6(coindb_cashdrive);
    // add left
    _test_add_7(coindb_cashdrive);
    // add key that already exists
    _test_add_8(coindb_cashdrive);
}
