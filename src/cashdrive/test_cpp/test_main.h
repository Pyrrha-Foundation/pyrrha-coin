// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TEST_TESTMAIN_H
#define TEST_TESTMAIN_H

#include "cashdrive/coindb.h"

#include <assert.h>

CCoinsViewDB* test_create();
void test_adds(CCoinsViewDB *coindb_cashdrive);
void test_spends(CCoinsViewDB *coindb_cashdrive);
//void test_second_root(CCoinsViewDB *coindb_cashdrive);
//void test_trim(CCoinsViewDB *coindb_cashdrive);

#endif // TEST_TESTMAIN_H
