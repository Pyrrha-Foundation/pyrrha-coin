// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CASHDRIVE_COINDBCURSOR_H
#define NEXA_CASHDRIVE_COINDBCURSOR_H

#include "blockstorage/dbabstract.h"
#include "chain.h"
#include "coins.h"
#include "dbwrapper.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

typedef uint8_t uint256_t[32];

inline std::string uint256t_ToString(const uint256_t &data)
{
    char psz[65];
    for (unsigned int i = 0; i < 32; i++)
    {
        sprintf(psz + (i * 2), "%02x", data[i]);
    }
    return std::string(psz, psz + 64);
}

class CoinEntryValue;

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor : public CCoinsViewCursor
{
private:
    CCoinsViewDBCursor(CDBIterator *pcursorIn, const uint256 &hashBlockIn)
        : CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn)
    {
    }
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, uint256_t> keyTmp;

    friend class CCoinsViewDB;

public:
    ~CCoinsViewDBCursor() {}
    bool GetKey(COutPoint &key) const;
    bool GetKey(uint256_t &key) const;
    bool GetValue(Coin &coin) const;
    bool GetValue(CoinEntryValue &coin) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();
};

#endif
