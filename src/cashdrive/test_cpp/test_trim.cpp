// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

extern void _test_second_root_validate_2(CCoinsViewDB *coindb_cashdrive);

void test_trim(CCoinsViewDB *coindb_cashdrive)
{
    // trim the trie
    coindb_cashdrive->_Trim();
    // the last validation in the second root tests (test section run immediately prior
    // to this one) should pass after trim with no alterations other than a lower expected
    // node count due to historical views of the trie being removed
    _test_second_root_validate_2(coindb_cashdrive);
    printf("trie trim passed \n");
}
