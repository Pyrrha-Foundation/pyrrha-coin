// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coindbcursor.h"

#include "coindb.h"

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    uint256_t _key;
    if (GetKey(_key))
    {
        key = COutPoint(uint256(_key));
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetKey(uint256_t &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN)
    {
        std::memcpy(key, keyTmp.second, UINT256_NUM_BYTES);
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    CoinEntryValue value;
    if (GetValue(value))
    {
        if (value.key_bits == 256)
        {
            coin = value.value;
        }
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(CoinEntryValue &coin) const
{
    return pcursor->GetValue(coin);
}
unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}
bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}
void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntryKey entry(keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry))
    {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    }
    else
    {
        keyTmp.first = entry.key_prefix;
    }
}
