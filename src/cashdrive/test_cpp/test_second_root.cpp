// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

void _test_create_second_root(CCoinsViewDB *coindb_cashdrive)
{
    assert(trie->current_root->root_group == 0);
    // create a new root
    bool res = BitwiseTrie_add_new_root(trie);
    assert(res == true);
    assert(trie->current_root->root_group == 1);
    printf("second_root create new root test passed \n");
}

void _test_second_root_add_1(CCoinsViewDB *coindb_cashdrive)
{
    // check the root first
    {
        TrieNode* root = trie->current_root;
        assert(root->key_bits == 0);
        assert(root->root_group == 1);
        // now check the right
        TrieNode* root_right = root->right;
        assert(root_right->key_bits == 6);
        // before the add the root group for the interior node should point to the last
        // root group because it has not been updated yet
        assert(root_right->root_group != root->root_group);
        assert(root_right->root_group == 0);
    }
    // add a new node
    uint256_t key = {200,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t scriptpubkey[5] = {0, 1, 2, 3, 4};
    int64_t amount = 10;
    bool res = BitwiseTrie_mint(trie, key, &amount, scriptpubkey, 5);
    assert(res == true);
    // should have added a new interior node on the root right with 1 key bit. and put the new
    // added node on the right of that.
    // check the root first
    {
        assert(trie->len_node_master_list == 14);
        TrieNode* root = trie->current_root;
        assert(root->key_bits == 0);
        assert(root->root_group == 1);
        // now check the right
        TrieNode* root_right = root->right;
        assert(root_right->key_bits == 1);
        assert(root_right->root_group == root->root_group);
        // should have added new node to the right
        TrieNode* root_right_right = root_right->right;
        assert(root_right_right->key_bits == 256);
        assert(root_right_right->key[0] == 200);
    }
    printf("second_root add-1 test passed \n");
}

void _test_second_root_spend_1(CCoinsViewDB *coindb_cashdrive)
{
    // spend a node
    uint256_t key = {130,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    bool res = BitwiseTrie_spend(trie, key);
    assert(res == true);
    assert(trie->len_node_master_list == 16);
    printf("second_root spend-1 test passed \n");
}

void _test_second_root_add_2(CCoinsViewDB *coindb_cashdrive)
{
    uint256_t key = {50,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t scriptpubkey[5] = {0, 1, 2, 3, 4};
    int64_t amount = 10;
    bool res = BitwiseTrie_mint(trie, key, &amount, scriptpubkey, 5);
    assert(res == true);
    assert(trie->len_node_master_list == 18);
    printf("second_root add-2 test passed \n");
}

void _test_second_root_validate_1(CCoinsViewDB *coindb_cashdrive)
{
    assert(trie->len_node_master_list == 18);
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
    TrieNode* root = trie->current_root;
    assert(root->key_bits == 0);
    assert(root->root_group == 1);
    // now check the right
    TrieNode* root_right = root->right;
    assert(root_right->key_bits == 1);
    assert(root_right->root_group == root->root_group);
    // go right
    TrieNode* root_right_right = root_right->right;
    assert(root_right_right->key_bits == 256);
    assert(root_right_right->root_group == root->root_group); // 1
    assert(root_right_right->key[0] == 200);
    // go back up and go left
    TrieNode* root_right_left = root_right->left;
    assert(root_right_left->key_bits == 6);
    assert(root_right_left->root_group == root->root_group); // 1
    // check leaf node
    TrieNode* root_right_left_left = root_right_left->left;
    assert(root_right_left_left->key_bits == 256);
    assert(root_right_left_left->key[0] == 129);
    // go back up and go right
    TrieNode* root_right_left_right = root_right_left->right;
    assert(root_right_left_right->key_bits == 256);
    assert(root_right_left_right->key[0] == 131);
    // right side verified, verify the left
    TrieNode* root_left = root->left;
    assert(root_left->key_bits == 1);
    assert(root_left->root_group == root->root_group);
    // go left
    TrieNode* root_left_left = root_left->left;
    assert(root_left_left->key_bits == 256);
    assert(root_left_left->key[0] == 50);
    // back up and go right
    // none of the interior nodes past this point should have the current root group
    // because the last time they were modified was in the previous root group
    TrieNode* root_left_right = root_left->right;
    assert(root_left_right->key_bits == 6);
    assert(root_left_right->root_group != root->root_group);
    assert(root_left_right->root_group == 0);
    // go left
    TrieNode* root_left_right_left = root_left_right->left;
    assert(root_left_right_left->key_bits == 7);
    assert(root_left_right_left->root_group != root->root_group);
    assert(root_left_right_left->root_group == 0);
    // check left leaf
    TrieNode* root_left_right_left_left = root_left_right_left->left;
    assert(root_left_right_left_left->key_bits == 256);
    assert(root_left_right_left_left->key[0] == 124);
    // check right leaf
    TrieNode* root_left_right_left_right = root_left_right_left->right;
    assert(root_left_right_left_right->key_bits == 256);
    assert(root_left_right_left_right->key[0] == 125);
    // go up 2 and check right branch
    TrieNode* root_left_right_right = root_left_right->right;
    assert(root_left_right_right->key_bits == 7);
    assert(root_left_right_right->root_group != root->root_group);
    assert(root_left_right_right->root_group == 0);
    // check left leaf
    TrieNode* root_left_right_right_left = root_left_right_right->left;
    assert(root_left_right_right_left->key_bits == 256);
    assert(root_left_right_right_left->key[0] == 126);
    // check right leaf
    TrieNode* root_left_right_right_right = root_left_right_right->right;
    assert(root_left_right_right_right->key_bits == 256);
    assert(root_left_right_right_right->key[0] == 127);

    printf("second_root end validate test passed \n");
}

void _test_second_root_spend_2(CCoinsViewDB *coindb_cashdrive)
{
    // spend a node
    uint256_t key = {127,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    bool res = BitwiseTrie_spend(trie, key);
    assert(res == true);
    printf("second_root spend-2 test passed \n");
}

void _test_second_root_validate_2(CCoinsViewDB *coindb_cashdrive, uint64_t expected_num_nodes)
{
    assert(trie->len_node_master_list == expected_num_nodes);
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
    TrieNode* root = trie->current_root;
    assert(root->key_bits == 0);
    // now check the right
    TrieNode* root_right = root->right;
    assert(root_right->key_bits == 1);
    // go right
    TrieNode* root_right_right = root_right->right;
    assert(root_right_right->key_bits == 256);
    assert(root_right_right->key[0] == 200);
    // go back up and go left
    TrieNode* root_right_left = root_right->left;
    assert(root_right_left->key_bits == 6);
    // check leaf node
    TrieNode* root_right_left_left = root_right_left->left;
    assert(root_right_left_left->key_bits == 256);
    assert(root_right_left_left->key[0] == 129);
    // go back up and go right
    TrieNode* root_right_left_right = root_right_left->right;
    assert(root_right_left_right->key_bits == 256);
    assert(root_right_left_right->key[0] == 131);
    // right side verified, verify the left
    TrieNode* root_left = root->left;
    assert(root_left->key_bits == 1);
    // go left
    TrieNode* root_left_left = root_left->left;
    assert(root_left_left->key_bits == 256);
    assert(root_left_left->key[0] == 50);
    // back up and go right
    // none of the interior nodes past this point should have the current root group
    // because the last time they were modified was in the previous root group
    TrieNode* root_left_right = root_left->right;
    assert(root_left_right->key_bits == 6);
    // go left
    TrieNode* root_left_right_left = root_left_right->left;
    assert(root_left_right_left->key_bits == 7);
    // check left leaf
    TrieNode* root_left_right_left_left = root_left_right_left->left;
    assert(root_left_right_left_left->key_bits == 256);
    assert(root_left_right_left_left->key[0] == 124);
    // check right leaf
    TrieNode* root_left_right_left_right = root_left_right_left->right;
    assert(root_left_right_left_right->key_bits == 256);
    assert(root_left_right_left_right->key[0] == 125);
    // go up 2 and check right branch
    TrieNode* root_left_right_right = root_left_right->right;
    assert(root_left_right_right->key_bits == 256);
    assert(root_left_right_right->key[0] == 126);

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
    _test_second_root_validate_2(coindb_cashdrive, 20);
}
