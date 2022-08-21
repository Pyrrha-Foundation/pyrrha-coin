// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coindb.h"

#include "blockstorage/blockstorage.h"

#include <stdint.h>

CCoinsViewDB *pcoinsdbview = nullptr;

static const char DB_COIN = 'C';

static const char DB_BEST_BLOCK = 'B';

struct CoinEntry
{
    COutPoint *outpoint;
    char key;
    CoinEntry(const COutPoint *ptr) : outpoint(const_cast<COutPoint *>(ptr)), key(DB_COIN) {}
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        s << key;
        s << outpoint->hash;
    }

    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> key;
        s >> outpoint->hash;
    }
};

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN)
    {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const { return pcursor->GetValue(coin); }
unsigned int CCoinsViewDBCursor::GetValueSize() const { return pcursor->GetValueSize(); }
bool CCoinsViewDBCursor::Valid() const { return keyTmp.first == DB_COIN; }
void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry))
    {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    }
    else
    {
        keyTmp.first = entry.key;
    }
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize,
    bool fMemory,
    bool fWipe,
    bool fObfuscate,
    COverrideOptions *overridecache)
    : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, fObfuscate, overridecache)
{
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const
{
    READLOCK(cs_utxo);
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const
{
    READLOCK(cs_utxo);
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const
{
    READLOCK(cs_utxo);
    return _GetBestBlock();
}

uint256 CCoinsViewDB::_GetBestBlock() const
{
    AssertLockHeld(cs_utxo);
    uint256 hashBestChain;
    std::string strmode = std::to_string(static_cast<int32_t>(BLOCK_DB_MODE));
    if (pblockdb)
    {
        // just use the int that is the db mode as its key for the best block it has
        if (!db.Read(strmode, hashBestChain))
            return uint256();
    }
    else
    {
        if (!db.Read(DB_BEST_BLOCK, hashBestChain))
            return uint256();
    }
    return hashBestChain;
}

uint256 CCoinsViewDB::GetBestBlock(BlockDBMode mode) const
{
    READLOCK(cs_utxo);
    return _GetBestBlock(mode);
}

uint256 CCoinsViewDB::_GetBestBlock(BlockDBMode mode) const
{
    AssertLockHeld(cs_utxo);
    uint256 hashBestChain;
    // if override isnt end, override the fetch to get the best block of a specific mode
    if (mode != END_STORAGE_OPTIONS)
    {
        std::string strmode = std::to_string(static_cast<int32_t>(mode));
        if (mode == SEQUENTIAL_BLOCK_FILES)
        {
            if (!db.Read(DB_BEST_BLOCK, hashBestChain))
                return uint256();
        }
        else
        {
            if (!db.Read(strmode, hashBestChain))
                return uint256();
        }
    }
    return hashBestChain;
}

void CCoinsViewDB::WriteBestBlock(const uint256 &hashBlock)
{
    WRITELOCK(cs_utxo);
    _WriteBestBlock(hashBlock);
}

void CCoinsViewDB::_WriteBestBlock(const uint256 &hashBlock)
{
    AssertWriteLockHeld(cs_utxo);
    std::string strmode = std::to_string(static_cast<int32_t>(BLOCK_DB_MODE));
    if (!hashBlock.IsNull())
    {
        if (pblockdb)
        {
            // just use the int that is the db mode as its key for the best block it has
            db.Write(strmode, hashBlock);
        }
        else // sequential files doesnt use the int of its mode for backwards compatibility reasons
        {
            db.Write(DB_BEST_BLOCK, hashBlock);
        }
    }
}

void CCoinsViewDB::WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode)
{
    WRITELOCK(cs_utxo);
    _WriteBestBlock(hashBlock);
}

void CCoinsViewDB::_WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode)
{
    AssertWriteLockHeld(cs_utxo);
    if (mode != END_STORAGE_OPTIONS)
    {
        std::string strmode = std::to_string(static_cast<int32_t>(mode));
        if (mode == SEQUENTIAL_BLOCK_FILES)
        {
            db.Write(DB_BEST_BLOCK, hashBlock);
        }
        else
        {
            db.Write(strmode, hashBlock);
        }
    }
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlock,
    const uint64_t nBestCoinHeight,
    size_t &nChildCachedCoinsUsage)
{
    WRITELOCK(cs_utxo);
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    size_t nBatchWrites = 0;
    size_t batch_size = nMaxDBBatchSize;
    size_t spent_coins = 0;

    LOG(COINDB, "starting committing process\n");
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();)
    {
        if (it->second.flags & CCoinsCacheEntry::DIRTY)
        {
            CoinEntry entry(&it->first);
            size_t nUsage = it->second.coin.DynamicMemoryUsage();
            if (it->second.coin.IsSpent())
            {
                batch.Erase(entry);
                spent_coins++;

                // Update the usage of the child cache before deleting the entry in the child cache
                nChildCachedCoinsUsage -= nUsage;
                it = mapCoins.erase(it);
            }
            else
            {
                batch.Write(entry, it->second.coin);

                // Only delete valid coins from the cache when we're nearly syncd.  During IBD, and also
                // if BlockOnly mode is turned on, these coins will be used, whereas, once the chain is
                // syncd we only need the coins that have come from accepting txns into the memory pool.
                if (IsChainNearlySyncd() && !fImporting && !fReindex && !fBlocksOnly &&
                    (nCoinCacheMaxSize < DEFAULT_HIGH_PERF_MEM_CUTOFF))
                {
                    // Update the usage of the child cache before deleting the entry in the child cache
                    nChildCachedCoinsUsage -= nUsage;
                    it = mapCoins.erase(it);
                }
                else
                {
                    it->second.flags = 0;
                    it++;
                }
            }
            changed++;

            // In order to prevent the spikes in memory usage that used to happen when we prepared large as
            // was possible, we instead break up the batches such that the performance gains for writing to
            // leveldb are still realized but the memory spikes are not seen.
            if (batch.SizeEstimate() > batch_size)
            {
                db.WriteBatch(batch);
                batch.Clear();
                nBatchWrites++;
            }
        }
        else
            it++;
        count++;
    }
    if (!hashBlock.IsNull())
        _WriteBestBlock(hashBlock);

    bool ret = db.WriteBatch(batch);
    LOG(COINDB,
        "Committing %u changed transactions (out of %u) to coin database with %u batch writes and %u spent coins...\n",
        (unsigned int)changed, (unsigned int)count, (unsigned int)nBatchWrites, (unsigned int)spent_coins);

    return ret;
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper *>(&db)->NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid())
    {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    }
    else
    {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

size_t CCoinsViewDB::EstimateSize() const
{
    READLOCK(cs_utxo);
    return db.EstimateSize(DB_COIN, (char)(DB_COIN + 1));
}

size_t CCoinsViewDB::TotalWriteBufferSize() const
{
    READLOCK(cs_utxo);
    return db.TotalWriteBufferSize();
}
