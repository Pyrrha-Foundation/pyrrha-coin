// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

static const CKeyID keyid1 = CKeyID(uint160(ParseHex("816115944e077fe7c803cfa57f29b36bf87c1d35")));

void _test_create_second_root(CCoinsViewDB *coindb_cashdrive)
{
    assert(coindb_cashdrive->_GetRootValue().root_group == 0);
    // create a new root
    coindb_cashdrive->_MakeNewRoot(1);
    assert(coindb_cashdrive->_GetRootValue().root_group == 1);
    printf("second_root create new root test passed \n");
}

void _test_second_root_add_1(CCoinsViewDB *coindb_cashdrive)
{
    // check the root first
    {
        const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
        assert(root.key_bits == 0);
        assert(root.root_group == 1);
        // now check the right
        CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
        assert(root_right.key_bits == 6);
        // before the add the root group for the interior node should point to the last
        // root group because it has not been updated yet
        assert(root_right.root_group != root.root_group);
        assert(root_right.root_group == 0);
    }
    // add a new node
    uint256_t key = {200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    int64_t amount = 10;
    CTxOut out(amount, script1);
    Coin coin(out, 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    // should have added a new interior node on the root right with 1 key bit. and put the new
    // added node on the right of that.
    // check the root first
    {
        const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
        assert(root.key_bits == 0);
        assert(root.root_group == 1);
        // now check the right
        CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
        assert(root_right.key_bits == 1);
        assert(root_right.root_group == root.root_group);
        // should have added new node to the right
        CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
        assert(root_right_right.key_bits == 256);
        assert(root_right_right.key[0] == 200);
    }
    printf("second_root add-1 test passed \n");
}

void _test_second_root_spend_1(CCoinsViewDB *coindb_cashdrive)
{
    // spend a node
    uint256_t key = {130,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    printf("second_root spend-1 test passed \n");
}

void _test_second_root_add_2(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    CScript script1;
    script1 << OP_DUP << OP_HASH160 << ToByteVector(keyid1) << OP_EQUALVERIFY << OP_CHECKSIG;
    int64_t amount = 10;
    CTxOut out(amount, script1);
    Coin coin(out, 1, false);
    bool res = coindb_cashdrive->Mint(outpoint, coin);
    assert(res == true);
    printf("second_root add-2 test passed \n");
}

void _test_second_root_validate_1(CCoinsViewDB *coindb_cashdrive)
{
    /*
    // full trie validation, only showing key[0] for brevity
    // trie should have final shape of:
    //                     root = XXXXXXXX
    //                    <-              ->
    //            0xxxxxxx                    1XXXXXXX
    //           /        \                    /     \
    //   00110010    011111XX            100000XX    11001000
    //              /        |             /     |
    //       0111110X         011111X  10000001  10000011
    //     /       |          /     |
    // 01111100  01111101  01111110 011111111
    //
    */
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(root.key_bits == 0);
    assert(root.root_group == 1);
    // now check the right
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 1);
    assert(root_right.root_group == root.root_group);
    // go right
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(root_right_right.key_bits == 256);
    assert(root_right_right.root_group == root.root_group); // 1
    assert(root_right_right.key[0] == 200);
    // go back up and go left
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(root_right_left.key_bits == 6);
    assert(root_right_left.root_group == root.root_group); // 1
    // check leaf node
    const CoinEntryValue root_right_left_left = coindb_cashdrive->_GetValueByKey(root_right_left.key_left);
    assert(root_right_left_left.key_bits == 256);
    assert(root_right_left_left.key[0] == 129);
    // go back up and go right
    const CoinEntryValue root_right_left_right = coindb_cashdrive->_GetValueByKey(root_right_left.key_right);
    assert(root_right_left_right.key_bits == 256);
    assert(root_right_left_right.key[0] == 131);
    // right side verified, verify the left
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 1);
    assert(root_left.root_group == root.root_group);
    // go left
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 256);
    assert(root_left_left.key[0] == 50);
    // back up and go right
    // none of the interior nodes past this point should have the current root group
    // because the last time they were modified was in the previous root group
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 6);
    assert(root_left_right.root_group != root.root_group);
    assert(root_left_right.root_group == 0);
    // go left
    const CoinEntryValue root_left_right_left = coindb_cashdrive->_GetValueByKey(root_left_right.key_left);
    assert(root_left_right_left.key_bits == 7);
    assert(root_left_right_left.root_group != root.root_group);
    assert(root_left_right_left.root_group == 0);
    // check left leaf
    const CoinEntryValue root_left_right_left_left = coindb_cashdrive->_GetValueByKey(root_left_right_left.key_left);
    assert(root_left_right_left_left.key_bits == 256);
    assert(root_left_right_left_left.key[0] == 124);
    // check right leaf
    const CoinEntryValue root_left_right_left_right = coindb_cashdrive->_GetValueByKey(root_left_right_left.key_right);
    assert(root_left_right_left_right.key_bits == 256);
    assert(root_left_right_left_right.key[0] == 125);
    // go up 2 and check right branch
    const CoinEntryValue root_left_right_right = coindb_cashdrive->_GetValueByKey(root_left_right.key_right);
    assert(root_left_right_right.key_bits == 7);
    assert(root_left_right_right.root_group != root.root_group);
    assert(root_left_right_right.root_group == 0);
    // check left leaf
    const CoinEntryValue root_left_right_right_left = coindb_cashdrive->_GetValueByKey(root_left_right_right.key_left);
    assert(root_left_right_right_left.key_bits == 256);
    assert(root_left_right_right_left.key[0] == 126);
    // check right leaf
    const CoinEntryValue root_left_right_right_right = coindb_cashdrive->_GetValueByKey(root_left_right_right.key_right);
    assert(root_left_right_right_right.key_bits == 256);
    assert(root_left_right_right_right.key[0] == 127);

    printf("second_root end validate test passed \n");
}

void _test_second_root_spend_2(CCoinsViewDB *coindb_cashdrive)
{
    // spend a node
    uint256_t key = {127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    printf("second_root spend-2 test passed \n");
}

void _test_second_root_validate_2(CCoinsViewDB *coindb_cashdrive)
{
    /*
    // full trie validation, only showing key[0] for brevity
    // trie should have final shape of:
    //                     root = XXXXXXXX
    //                    <-              ->
    //            0xxxxxxx                    1XXXXXXX
    //           /        \                    /     \
    //   00110010    011111XX            100000XX    11001000
    //              /        |             /     |
    //       0111110X      01111110   10000001  10000011
    //     /       |
    // 01111100  01111101
    //
    */
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(root.key_bits == 0);
    // now check the right
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 1);
    // go right
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(root_right_right.key_bits == 256);
    assert(root_right_right.key[0] == 200);
    // go back up and go left
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(root_right_left.key_bits == 6);
    // check leaf node
    const CoinEntryValue root_right_left_left = coindb_cashdrive->_GetValueByKey(root_right_left.key_left);
    assert(root_right_left_left.key_bits == 256);
    assert(root_right_left_left.key[0] == 129);
    // go back up and go right
    const CoinEntryValue root_right_left_right = coindb_cashdrive->_GetValueByKey(root_right_left.key_right);
    assert(root_right_left_right.key_bits == 256);
    assert(root_right_left_right.key[0] == 131);
    // right side verified, verify the left
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 1);
    // go left
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 256);
    assert(root_left_left.key[0] == 50);
    // back up and go right
    // none of the interior nodes past this point should have the current root group
    // because the last time they were modified was in the previous root group
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 6);
    // go left
    const CoinEntryValue root_left_right_left = coindb_cashdrive->_GetValueByKey(root_left_right.key_left);
    assert(root_left_right_left.key_bits == 7);
    // check left leaf
    const CoinEntryValue root_left_right_left_left = coindb_cashdrive->_GetValueByKey(root_left_right_left.key_left);
    assert(root_left_right_left_left.key_bits == 256);
    assert(root_left_right_left_left.key[0] == 124);
    // check right leaf
    const CoinEntryValue root_left_right_left_right = coindb_cashdrive->_GetValueByKey(root_left_right_left.key_right);
    assert(root_left_right_left_right.key_bits == 256);
    assert(root_left_right_left_right.key[0] == 125);
    // go up 2 and check right branch
    const CoinEntryValue root_left_right_right = coindb_cashdrive->_GetValueByKey(root_left_right.key_right);
    assert(root_left_right_right.key_bits == 256);
    assert(root_left_right_right.key[0] == 126);

    printf("second_root end validate test passed \n");
}

void test_second_root(CCoinsViewDB *coindb_cashdrive)
{
    // make a new root
    _test_create_second_root(coindb_cashdrive);
    // add a node on the new root
    _test_second_root_add_1(coindb_cashdrive);
    // spend an existing node
    _test_second_root_spend_1(coindb_cashdrive);
    // add a new node
    _test_second_root_add_2(coindb_cashdrive);
    // validate the trie
    _test_second_root_validate_1(coindb_cashdrive);
    // spend an existing node
    _test_second_root_spend_2(coindb_cashdrive);
    // validate the trie
    _test_second_root_validate_2(coindb_cashdrive);
}
