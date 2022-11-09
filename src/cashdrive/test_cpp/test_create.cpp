// Copyright (c) 2022 Dr. Peter R. Rizun
// Copyright (c) 2022 Greg Griffith
// Copyright (c) 2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test_main.h"

CCoinsViewDB* test_create()
{
    return new CCoinsViewDB(1 << 23, true, false, false, nullptr, "cashdrive-test");
}
