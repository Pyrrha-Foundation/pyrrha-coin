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

static const char DB_COIN = 'C';
static const char DB_CASHDRIVE_COIN = 'c';
static const char DB_ROOT_KEY = 'r';
static const char DB_LAST_ROOT_KEY = 'R';

extern const char DB_BEST_BLOCK;
static const char DB_LAST_KEY_USED = 'K';

static constexpr uint32_t UINT256_NUM_BYTES = 32;

static constexpr uint256_t UINT256_ZERO = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static constexpr uint256_t UINT256_MAX = {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};

static constexpr uint8_t BIN_00000000 = 0;
static constexpr uint8_t BIN_00000001 = 1;
static constexpr uint8_t BIN_00000010 = 2;
static constexpr uint8_t BIN_00000100 = 4;
static constexpr uint8_t BIN_00001000 = 8;
static constexpr uint8_t BIN_00010000 = 16;
static constexpr uint8_t BIN_00100000 = 32;
static constexpr uint8_t BIN_01000000 = 64;
static constexpr uint8_t BIN_10000000 = 128;

static constexpr uint8_t BIN_01111111 = 127;
static constexpr uint8_t BIN_00111111 = 63;
static constexpr uint8_t BIN_00011111 = 31;
static constexpr uint8_t BIN_00001111 = 15;
static constexpr uint8_t BIN_00000111 = 7;
static constexpr uint8_t BIN_00000011 = 3;

static constexpr uint8_t BIN_11111111 = 255;

static constexpr uint8_t BIN_11000000 = 192;
static constexpr uint8_t BIN_11100000 = 224;
static constexpr uint8_t BIN_11110000 = 240;
static constexpr uint8_t BIN_11111000 = 248;
static constexpr uint8_t BIN_11111100 = 252;
static constexpr uint8_t BIN_11111110 = 254;


struct CoinEntryKey
{
    char key_prefix;
    uint256_t key;
    CoinEntryKey(const uint256 value) : key_prefix(DB_COIN)
    {
        value.GetRaw(key);
    }
    CoinEntryKey(const uint256_t value) : key_prefix(DB_COIN)
    {
        std::memcpy(key, value, UINT256_NUM_BYTES);
    }
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        s << key_prefix;
        uint256 key256(key);
        s << key256;
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> key_prefix;
        uint256 key256;
        s >> key256;
        key256.GetRaw(key);
    }
};

struct CoinEntryValue
{
    // cashdrive metadata
    uint32_t key_bits;
    uint32_t root_group;
    uint256_t fingerprint; // in leaf nodes, the key is also the fingerprint
    uint256_t key_parent; // not an outpoint hash
    uint256_t key_left; // not an outpoint hash
    uint256_t key_right; // not an outpoint hash
    // utxo data
    uint256_t key; // outpoint hash
    Coin value;

    CoinEntryValue()
    {
        SetNull();
    }

    CoinEntryValue(const CoinEntryValue &a)
    {
        key_bits = a.key_bits;
        root_group = a.root_group;
        std::memcpy(fingerprint, a.fingerprint, UINT256_NUM_BYTES);
        std::memcpy(key_parent, a.key_parent, UINT256_NUM_BYTES);
        std::memcpy(key_left, a.key_left, UINT256_NUM_BYTES);
        std::memcpy(key_right, a.key_right, UINT256_NUM_BYTES);
        std::memcpy(key, a.key, UINT256_NUM_BYTES);
        value = a.value;
    }

    std::string ToString()
    {
        return strprintf("key_bits = %u, root_group = %u, fingerprint = %s, key_parent = %s, key_left = %s, key_right = %s, key = %s, value = %s \n", key_bits, root_group,
            uint256t_ToString(fingerprint).c_str(), uint256t_ToString(key_parent).c_str(), uint256t_ToString(key_left).c_str(), uint256t_ToString(key_right).c_str(),
            uint256t_ToString(key).c_str(), value.out.ToString().c_str());
    }

    void SetNull()
    {
        key_bits = 0;
        root_group = 0;
        std::memset(fingerprint, 0, UINT256_NUM_BYTES);
        std::memset(key_parent, 0, UINT256_NUM_BYTES);
        std::memset(key_left, 0, UINT256_NUM_BYTES);
        std::memset(key_right, 0, UINT256_NUM_BYTES);
        std::memset(key, 0, UINT256_NUM_BYTES);
        value.Clear();
    }

    // fingerprint is not part of == purely because it may not be the most recent
    bool operator==(const CoinEntryValue &a) const
    {
        return (key_bits == a.key_bits && root_group == a.root_group
            && std::memcmp(key_parent, a.key_parent, UINT256_NUM_BYTES) == 0
            && std::memcmp(key_left, a.key_left, UINT256_NUM_BYTES) == 0
            && std::memcmp(key_right, a.key_right, UINT256_NUM_BYTES) == 0
            && std::memcmp(key, a.key, UINT256_NUM_BYTES) == 0
            && value == a.value);
    }
    bool operator!=(const CoinEntryValue &a) const
    {
        return !(*this == a);
    }

    void operator=(const CoinEntryValue &a)
    {
        key_bits = a.key_bits;
        root_group = a.root_group;
        std::memcpy(fingerprint, a.fingerprint, UINT256_NUM_BYTES);
        std::memcpy(key_parent, a.key_parent, UINT256_NUM_BYTES);
        std::memcpy(key_left, a.key_left, UINT256_NUM_BYTES);
        std::memcpy(key_right, a.key_right, UINT256_NUM_BYTES);
        std::memcpy(key, a.key, UINT256_NUM_BYTES);
        value = a.value;
    }

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        s << key_bits;
        s << root_group;
        uint256 fingerprint256(fingerprint);
        uint256 key_parent256(key_parent);
        uint256 key_left256(key_left);
        uint256 key_right256(key_right);
        uint256 key256(key);
        s << fingerprint256;
        s << key_parent256;
        s << key_left256;
        s << key_right256;
        s << key256;
        s << value;
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> key_bits;
        s >> root_group;
        uint256 fingerprint256;
        s >> fingerprint256;
        fingerprint256.GetRaw(fingerprint);
        uint256 key_parent256;
        s >> key_parent256;
        key_parent256.GetRaw(key_parent);
        uint256 key_left256;
        s >> key_left256;
        key_left256.GetRaw(key_left);
        uint256 key_right256;
        s >> key_right256;
        key_right256.GetRaw(key_right);
        uint256 key256;
        s >> key256;
        key256.GetRaw(key);
        s >> value;
    }
};

static const uint256_t INVALID_KEY = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const CoinEntryValue INVALID_ENTRY;

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
    bool GetKey(COutPoint &key) const
    {
        // intentionally left blank
        // this functiton should not be used
        // but is required by the abstract base class
        return false;
    }
    bool GetKey(uint256_t &key) const;
    bool GetValue(Coin &coin) const
    {
        // intentionally left blank
        // this functiton should not be used
        // but is required by the abstract base class
        return false;
    }
    bool GetValue(CoinEntryValue &coin) const;
    unsigned int GetValueSize() const;

    bool Valid() const;
    void Next();
};

/** CCoinsView backed by the coin database (chainstate/) */

// TODO
// the key is an incremental 256 bit hexidecimal number, starts at 0, never resets.
// need to store the keys of the root hashes somewhere to differentiate views
// the root group is the block height, if not the block height needs to be stored in root nodes
// the value of the current root group should be stored somewhere for easy access.
// flush after every block?

class CCoinsViewDB : public CCoinsView
{
private:
    uint256_t current_root_key;
    uint32_t current_root_group;
    uint256_t next_db_key_available;

protected:
    CDBWrapper db;

private:
    std::pair<CoinEntryKey, CoinEntryValue> _make_new_interior_node(const uint256_t &parent_key,
        CoinEntryValue& parent_value,
        const uint256_t &replacing_key,
        CoinEntryValue& replacing_value,
        const uint256_t &key);
    std::pair<CoinEntryKey, CoinEntryValue> _copy_entry_with_new_parent(const CoinEntryValue &value,
        const uint256_t &new_parent_key,
        const CoinEntryValue &new_parent_value);

    void _MakeNewRoot();
    void _IncrementLastKeyUsed();
    void _WriteLastKeyUsed();
    CoinEntryValue _FindCoin(const COutPoint &outpoint) const;
    CoinEntryValue _UpdateFingerprint(const uint256_t &parent_key);


public:
    CCoinsViewDB(size_t nCacheSize,
        bool fMemory = false,
        bool fWipe = false,
        bool fObfuscate = false,
        COverrideOptions *overridecache = nullptr,
        std::string path = "chainstate");

    CoinEntryValue _GetRootValue() const;
    CoinEntryValue _GetValueByKey(const uint256_t &key) const; // used only in tests
    CoinEntryValue _GetValueByOutpoint(const COutPoint &outpoint) const; // used only in tests
    void _debug_print_trie();
    uint256 GetFingerprint();

    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool _HaveCoin(const COutPoint &outpoint) const;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const;
    uint256 _GetBestBlock() const override;
    uint256 GetBestBlock(BlockDBMode mode) const;
    uint256 _GetBestBlock(BlockDBMode mode) const;
    void WriteBestBlock(const uint256 &hashBlock);
    void _WriteBestBlock(const uint256 &hashBlock);
    void WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode);
    void _WriteBestBlock(const uint256 &hashBlock, BlockDBMode mode);
    bool Mint(const COutPoint &outpoint, const Coin &coin);
    bool Spend(const COutPoint &outpoint);
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
