// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CASHDRIVE_COINDB_H
#define NEXA_CASHDRIVE_COINDB_H

#include "blockstorage/dbabstract.h"
#include "chain.h"
#include "coins.h"
#include "dbwrapper.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor : public CCoinsViewCursor
{
private:
    CCoinsViewDBCursor(CDBIterator *pcursorIn, const uint256 &hashBlockIn)
        : CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn)
    {
    }
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;

public:
    ~CCoinsViewDBCursor() {}
    bool GetKey(COutPoint &key) const;
    bool GetValue(Coin &coin) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();
};


/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB : public CCoinsView
{
protected:
    CDBWrapper db;

public:
    CCoinsViewDB(size_t nCacheSize,
        bool fMemory = false,
        bool fWipe = false,
        bool fObfuscate = false,
        COverrideOptions *overridecache = nullptr);

    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const;
    uint256 _GetBestBlock() const override;
    uint256 GetBestBlock(BlockDBMode mode) const;
    uint256 _GetBestBlock(BlockDBMode mode) const;
    void WriteBestBlock(const uint256 &hashBlock);
    void _WriteBestBlock(const uint256 &hashBlock);
    void WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode);
    void _WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode);
    bool BatchWrite(CCoinsMap &mapCoins,
        const uint256 &hashBlock,
        const uint64_t nBestCoinHeight,
        size_t &nChildCachedCoinsUsage) override;
    CCoinsViewCursor *Cursor() const override;

    size_t EstimateSize() const override;

    //! Return the current memory allocated for the write buffers
    size_t TotalWriteBufferSize() const;
};

/** Global variable that points to the coins database */
extern CCoinsViewDB *pcoinsdbview;

#endif // NEXA_CASHDRIVE_COINDB_H
