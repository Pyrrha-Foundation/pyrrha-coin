// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "test_main.h"
#include "test/test_nexa.h"

BOOST_FIXTURE_TEST_SUITE(cashdrive_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(TEST_ALL_CASHDRIVE)
{
    // all test functions are void. if they fail it will assert
    CCoinsViewDB *coindb_cashdrive = test_create();
    // build a trie
    test_adds(coindb_cashdrive);
    // spend the entire trie back to a single root.
    test_spends(coindb_cashdrive);
    // test fingerprint
    test_fingerprint(coindb_cashdrive);
    // destroy the (empty) trie
    //BitwiseTrie_destroy(coindb_cashdrive);
    // make a new trie
    //coindb_cashdrive = test_create();
    // build a trie again
    //test_adds(coindb_cashdrive);
    // start a new root and change the trie.
    //test_second_root(coindb_cashdrive);
    // trim the trie to the last root
    //test_trim(coindb_cashdrive);
    // destroy the (populated) trie
    //BitwiseTrie_destroy(coindb_cashdrive);
    printf("\nALL CASHDRIVE TESTS PASSED \n");
}

BOOST_AUTO_TEST_SUITE_END()
