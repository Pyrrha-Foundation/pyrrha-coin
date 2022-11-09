// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

static void _test_spend_1(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // now check the right
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    //assert(root_right->parent == root);
    assert(root_right.key_bits == 6);
    assert(root_right.root_group == root.root_group);
    // the first leaf node is root right left
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(std::memcmp(root_right_left.key_parent, root.key_right, UINT256_NUM_BYTES) == 0);
    assert(root_right_left.key_bits == 256);
    assert(root_right_left.key[0] == 129);
    assert(std::memcmp(root_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // go right
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(std::memcmp(root_right_right.key_parent, root.key_right, UINT256_NUM_BYTES) == 0);
    assert(root_right_right.key_bits == 7);
    assert(root_right_right.root_group == root.root_group);
    // leaf node 10000010
    const CoinEntryValue root_right_right_left = coindb_cashdrive->_GetValueByKey(root_right_right.key_left);
    assert(std::memcmp(root_right_right_left.key_parent, root_right.key_right, UINT256_NUM_BYTES) == 0);
    assert(root_right_right_left.key_bits == 256);
    assert(root_right_right_left.key[0] == 130);
    assert(std::memcmp(root_right_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    const CoinEntryValue root_right_right_right = coindb_cashdrive->_GetValueByKey(root_right_right.key_right);
    assert(std::memcmp(root_right_right_right.key_parent, root_right.key_right, UINT256_NUM_BYTES) == 0);
    assert(root_right_right_right.key_bits == 256);
    assert(root_right_right_right.key[0] == 131);
    assert(std::memcmp(root_right_right_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_right_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // right side verified, verify the left
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    //assert(root_left->parent == root);
    assert(root_left.key_bits == 6);
    assert(root_left.root_group == root.root_group);
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(std::memcmp(root_left_left.key_parent, root.key_left, UINT256_NUM_BYTES) == 0);
    assert(root_left_left.key_bits == 7);
    assert(root_left_left.root_group == root.root_group);
    // the two leaf nodes on root left left
    const CoinEntryValue root_left_left_left = coindb_cashdrive->_GetValueByKey(root_left_left.key_left);
    assert(std::memcmp(root_left_left_left.key_parent, root_left.key_left, UINT256_NUM_BYTES) == 0);
    assert(root_left_left_left.key_bits == 256);
    assert(root_left_left_left.key[0] == 124);
    assert(std::memcmp(root_left_left_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_left_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    const CoinEntryValue root_left_left_right = coindb_cashdrive->_GetValueByKey(root_left_left.key_right);
    assert(std::memcmp(root_left_left_right.key_parent, root_left.key_left, UINT256_NUM_BYTES) == 0);
    assert(root_left_left_right.key[0] == 125);
    assert(root_left_left_right.key_bits == 256);
    assert(std::memcmp(root_left_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // go back to root left and go right, make sure the node was spent and
    // this is now a leaf node
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(std::memcmp(root_left_right.key_parent, root.key_left, UINT256_NUM_BYTES) == 0);
    assert(root_left_right.key_bits == 256);
    assert(root_left_right.key[0] == 126);
    assert(std::memcmp(root_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-1 test passed \n");
}

static void _test_spend_2(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {129,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // now check the right, it should have keybits of 7 now because the left branch of
    // the keybit 6 interior node before it was spent and that keybit6 interior node was
    // trimmed
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 7);
    assert(root_right.root_group == root.root_group);
    // the first leaf node is root right left
    // leaf node 10000010
    const CoinEntryValue root_right_left = coindb_cashdrive->_GetValueByKey(root_right.key_left);
    assert(root_right_left.key_bits == 256);
    assert(root_right_left.key[0] == 130);
    assert(std::memcmp(root_right_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // leaf node 10000011
    const CoinEntryValue root_right_right = coindb_cashdrive->_GetValueByKey(root_right.key_right);
    assert(root_right_right.key_bits == 256);
    assert(root_right_right.key[0] == 131);
    assert(std::memcmp(root_right_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
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
    // go back to root left and go right, make sure the node was spent and
    // this is now a leaf node
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 256);
    assert(root_left_right.key[0] == 126);
    assert(std::memcmp(root_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-2 test passed \n");
}

static void _test_spend_3(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {131,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // there is only 1 leaf node on the right side of the tree remaining,
    // it should be directly to the right of root and all interior nodes above it should
    // have been trimmed after this spend
    const CoinEntryValue root_right = coindb_cashdrive->_GetValueByKey(root.key_right);
    assert(root_right.key_bits == 256);
    assert(root_right.key[0] == 130); // leaf node 10000010
    assert(std::memcmp(root_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
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
    // go back to root left and go right, make sure the node was spent and
    // this is now a leaf node
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 256);
    assert(root_left_right.key[0] == 126);
    assert(std::memcmp(root_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-3 test passed \n");
}

static void _test_spend_4(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {130,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // all leaf nodes on the right side of the tree have now been spent, root right should
    // now be null
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
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
    // go back to root left and go right, make sure the node was spent and
    // this is now a leaf node
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key_bits == 256);
    assert(root_left_right.key[0] == 126);
    assert(std::memcmp(root_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-4 test passed \n");
}

static void _test_spend_5(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {126,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // all leaf nodes on the right side of the tree have now been spent, root right should
    // now be null
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // right side verified, verify the left
    // it should be a 7 keybit interior node because the 6 keybit interior node only had 1 branch
    // remaining after this spend and should have been trimmed
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key_bits == 7);
    assert(root_left.root_group == root.root_group);
    // the two leaf nodes on root left left
    const CoinEntryValue root_left_left = coindb_cashdrive->_GetValueByKey(root_left.key_left);
    assert(root_left_left.key_bits == 256);
    assert(root_left_left.key[0] == 124);
    assert(std::memcmp(root_left_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    const CoinEntryValue root_left_right = coindb_cashdrive->_GetValueByKey(root_left.key_right);
    assert(root_left_right.key[0] == 125);
    assert(root_left_right.key_bits == 256);
    assert(std::memcmp(root_left_right.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left_right.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-5 test passed \n");
}

static void _test_spend_6(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {124,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // check the root first
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    // all leaf nodes on the right side of the tree have now been spent, root right should
    // now be null
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    // right side verified, verify the left
    // there is only 1 leaf node remaining, it should be directly on the root left
    const CoinEntryValue root_left = coindb_cashdrive->_GetValueByKey(root.key_left);
    assert(root_left.key[0] == 125);
    assert(root_left.key_bits == 256);
    assert(std::memcmp(root_left.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root_left.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-6 test passed \n");
}

static void _test_spend_7(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {125,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    COutPoint outpoint;
    outpoint.hash = uint256(key);
    bool res = coindb_cashdrive->Spend(outpoint);
    assert(res == true);
    // all nodes should be spent, assert right and left of root are both NULL
    const CoinEntryValue root = coindb_cashdrive->_GetRootValue();
    assert(std::memcmp(root.key_parent, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key, UINT256_ZERO, UINT256_NUM_BYTES) == 0);
    assert(root.key_bits == 0);
    assert(std::memcmp(root.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    assert(std::memcmp(root.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
    printf("Spend-7 test passed \n");
}

void test_spends(CCoinsViewDB *coindb_cashdrive)
{

    _test_spend_1(coindb_cashdrive);

    _test_spend_2(coindb_cashdrive);

    _test_spend_3(coindb_cashdrive);

    _test_spend_4(coindb_cashdrive);

    _test_spend_5(coindb_cashdrive);

    _test_spend_6(coindb_cashdrive);

    _test_spend_7(coindb_cashdrive);
}
