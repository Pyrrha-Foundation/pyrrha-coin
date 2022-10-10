// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coindb.h"

#include "blockstorage/blockstorage.h"

#include <stdint.h>

CCoinsViewDB *pcoinsdbview = nullptr;

static const bool cashdrive_debug = false;

static int _compare_key_bits(const uint256_t a, const uint256_t b, const uint32_t b_key_bits)
{
    const uint32_t bytes_to_check = b_key_bits / 8;
    const uint32_t bits_after_bytes = b_key_bits % 8;
    uint256_t keybit_mask;
    std::memset(keybit_mask, 0, UINT256_NUM_BYTES);
    uint32_t i = 0;
    for (; i < bytes_to_check; ++i)
    {
        keybit_mask[i] = 255;
    }
    uint8_t bin_bits_after = BIN_00000000;
    if (bits_after_bytes == 1)
    {
        bin_bits_after = BIN_10000000;
    }
    else if(bits_after_bytes == 2)
    {
        bin_bits_after = BIN_11000000;
    }
    else if(bits_after_bytes == 3)
    {
        bin_bits_after = BIN_11100000;
    }
    else if(bits_after_bytes == 4)
    {
        bin_bits_after = BIN_11110000;
    }
    else if(bits_after_bytes == 5)
    {
        bin_bits_after = BIN_11111000;
    }
    else if(bits_after_bytes == 6)
    {
        bin_bits_after = BIN_11111100;
    }
    else if (bits_after_bytes == 7)
    {
        bin_bits_after = BIN_11111110;
    }
    keybit_mask[i] = bin_bits_after;
    uint256_t a_keybits;
    uint256_t b_keybits;
    for (uint32_t j = 0; j < UINT256_NUM_BYTES; ++j)
    {
        a_keybits[j] = a[j] & keybit_mask[j];
        b_keybits[j] = b[j] & keybit_mask[j];
    }
    return std::memcmp(a_keybits, b_keybits, UINT256_NUM_BYTES);
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

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize,
    bool fMemory,
    bool fWipe,
    bool fObfuscate,
    COverrideOptions *overridecache,
    std::string path)
    : db(GetDataDir() / path, nCacheSize, fMemory, fWipe, fObfuscate, overridecache)
{
    uint256 current_root_key256;
    if (!db.Read(DB_LAST_ROOT_KEY, current_root_key256))
    {
        // this is the first time cashdrive has been used, set the first root
        current_root_group = 0;
        std::memset(next_db_key_available, 0, UINT256_NUM_BYTES);
        next_db_key_available[0] = 1; // key is 1 for the first root, key 0 is the invalid key
        std::memcpy(current_root_key, next_db_key_available, UINT256_NUM_BYTES);
        _IncrementLastKeyUsed(); // key is 2 for the next key needed
        assert(std::memcmp(current_root_key, UINT256_ZERO, UINT256_NUM_BYTES) != 0);
        db.Write(DB_ROOT_KEY, uint256(current_root_key));
        db.Write(DB_LAST_ROOT_KEY, uint256(current_root_key));
        CoinEntryValue initial_root_value;
        initial_root_value.SetNull();
        initial_root_value.root_group = current_root_group;
        db.Write(CoinEntryKey(current_root_key), initial_root_value);
        db.Write(DB_LAST_KEY_USED, uint256(next_db_key_available));
    }
    else
    {
        current_root_key256.GetRaw(current_root_key);
        // we were able to read the root key
        CoinEntryValue root_value;
        db.Read(CoinEntryKey(current_root_key), root_value);
        current_root_group = root_value.root_group;
        uint256 next_db_key_available256;
        db.Read(DB_LAST_KEY_USED, next_db_key_available256);
        next_db_key_available256.GetRaw(next_db_key_available);
    }
}

std::pair<CoinEntryKey, CoinEntryValue> CCoinsViewDB::_make_new_interior_node(const uint256_t &parent_key,
    CoinEntryValue& parent_value,
    const uint256_t &replacing_key,
    CoinEntryValue& replacing_value,
    const uint256_t &key)
{
    CDBBatch batch(db);
    CoinEntryKey interior_key(next_db_key_available);
    _IncrementLastKeyUsed();
    CoinEntryValue interior_value;
    interior_value.SetNull();
    std::memcpy(interior_value.key, key, UINT256_NUM_BYTES);
    interior_value.root_group = parent_value.root_group;
    // calculate key_bits
    uint32_t i = 0;
    while(std::memcmp(&key[i], &replacing_value.key[i], 1) == 0)
    {
        ++i;
    }
    interior_value.key_bits = 8 * i;
    // byte i is the differing byte, check the bits
    // do not check the last bit because this is an interior node
    uint8_t bin_number = BIN_00000000;
    uint8_t wild_bit_mask = BIN_00000000;
    if ((BIN_10000000 & key[i]) != (BIN_10000000 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 0;
        bin_number = BIN_10000000;
        wild_bit_mask = BIN_00000000;
    }
    else if ((BIN_01000000 & key[i]) != (BIN_01000000 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 1;
        bin_number = BIN_01000000;
        wild_bit_mask = BIN_10000000;
    }
    else if ((BIN_00100000 & key[i]) != (BIN_00100000 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 2;
        bin_number = BIN_00100000;
        wild_bit_mask = BIN_11000000;
    }
    else if ((BIN_00010000 & key[i]) != (BIN_00010000 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 3;
        bin_number = BIN_00010000;
        wild_bit_mask = BIN_11100000;
    }
    else if ((BIN_00001000 & key[i]) != (BIN_00001000 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 4;
        bin_number = BIN_00001000;
        wild_bit_mask = BIN_11110000;
    }
    else if ((BIN_00000100 & key[i]) != (BIN_00000100 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 5;
        bin_number = BIN_00000100;
        wild_bit_mask = BIN_11111000;
    }
    else if ((BIN_00000010 & key[i]) != (BIN_00000010 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 6;
        bin_number = BIN_00000010;
        wild_bit_mask = BIN_11111100;
    }
    else if ((BIN_00000001 & key[i]) != (BIN_00000001 & replacing_value.key[i]))
    {
        interior_value.key_bits = interior_value.key_bits + 7;
        bin_number = BIN_00000001;
        wild_bit_mask = BIN_11111110;
    }
    // 0 out all of the wild bits in the interior node
    // it is useful for later if they are all set to 0
    // setting them to 0 does not affect the shape of the trie
    uint32_t k = i;
    interior_value.key[k] &= wild_bit_mask;
    ++k;
    for (; k < UINT256_NUM_BYTES; ++k)
    {
        interior_value.key[k] &= BIN_00000000;
    }
    // check if the first not key bit is 0 for left, 1 for right
    if ((replacing_value.key[i] & bin_number) == BIN_00000000)
    {
        std::memcpy(interior_value.key_left, replacing_key, UINT256_NUM_BYTES);
        std::memcpy(interior_value.key_right, INVALID_KEY, UINT256_NUM_BYTES);
        if (cashdrive_debug)
        {
            LOGA("putting the replaced node on the new interior node left \n");
        }
    }
    else
    {
        std::memcpy(interior_value.key_left, INVALID_KEY, UINT256_NUM_BYTES);
        std::memcpy(interior_value.key_right, replacing_key, UINT256_NUM_BYTES);
        if (cashdrive_debug)
        {
            LOGA("putting the replaced node on the new interior node right \n");
        }
    }
    // we can determine if this is replacing a parent's left or right node by the value of
    // the first wild bit
    // 0 is left, 1 is right
    // the exeption is when the parent is the root node
    if (parent_value.key_bits == 0)
    {
        CoinEntryValue current_root_value;
        current_root_value.SetNull();
        if (!db.Read(CoinEntryKey(current_root_key), current_root_value))
        {
            assert(false);
        }
        // the parent is a root node but we do not know which one, grab the current root node
        if ((interior_value.key[0] & BIN_10000000) == BIN_10000000)
        {
            std::memcpy(current_root_value.key_right, interior_key.key, UINT256_NUM_BYTES);
        }
        else
        {
            std::memcpy(current_root_value.key_left, interior_key.key, UINT256_NUM_BYTES);
        }
        std::memcpy(interior_value.key_parent, current_root_key, UINT256_NUM_BYTES);
        // the root has been updated, write the changes to the db
        batch.Write(CoinEntryKey(current_root_key), current_root_value);
    }
    else
    {
        const uint8_t parent_key_bytes_count = parent_value.key_bits / 8;
        const uint8_t parent_key_bits_mod = parent_value.key_bits % 8;
        // both of these can not be 0. this should never be true, if it were the root node case should
        // have been triggered
        assert((parent_key_bytes_count != 0 || parent_key_bits_mod != 0));
        uint8_t parent_wild_bit_number = BIN_00000000;
        if (parent_key_bits_mod == 0)
        {
            parent_wild_bit_number = BIN_10000000;
        }
        else if (parent_key_bits_mod == 1)
        {
            parent_wild_bit_number = BIN_01000000;
        }
        else if (parent_key_bits_mod == 2)
        {
            parent_wild_bit_number = BIN_00100000;
        }
        else if (parent_key_bits_mod == 3)
        {
            parent_wild_bit_number = BIN_00010000;
        }
        else if (parent_key_bits_mod == 4)
        {
            parent_wild_bit_number = BIN_00001000;
        }
        else if (parent_key_bits_mod == 5)
        {
            parent_wild_bit_number = BIN_00000100;
        }
        else if (parent_key_bits_mod == 6)
        {
            parent_wild_bit_number = BIN_00000010;
        }
        else if (parent_key_bits_mod == 7)
        {
            parent_wild_bit_number = BIN_00000001;
        }
        bool isParentRight = key[parent_key_bytes_count] & parent_wild_bit_number;
        if (isParentRight)
        {
            if (cashdrive_debug)
            {
                LOGA("putting the new interior node on the parent right \n");
            }
            std::memcpy(parent_value.key_right, interior_key.key, UINT256_NUM_BYTES);
        }
        else // left
        {
            if (cashdrive_debug)
            {
                LOGA("putting the new interior node on the parent left \n");
            }
            std::memcpy(parent_value.key_left, interior_key.key, UINT256_NUM_BYTES);
        }
        // parent has been updated, write the changes to the db
        batch.Write(CoinEntryKey(parent_key), parent_value);
        std::memcpy(interior_value.key_parent, replacing_value.key_parent, UINT256_NUM_BYTES);
    }
    std::memcpy(replacing_value.key_parent, interior_key.key, UINT256_NUM_BYTES);
    // replacing value has been updated, write the changes to the db
    batch.Write(CoinEntryKey(replacing_key), replacing_value);
    // before we return, write the new interior node
    // write the new node
    batch.Write(interior_key, interior_value);
    db.WriteBatch(batch);
    return std::make_pair(interior_key, interior_value);
}

// makes a copy of node with the parent set to new_parent, the root group is set to the
// same root group as the parent
std::pair<CoinEntryKey, CoinEntryValue> CCoinsViewDB::_copy_entry_with_new_parent(const CoinEntryValue &value,
    const uint256_t &new_parent_key,
    const CoinEntryValue &new_parent_value)
{
    CoinEntryKey copy_key(next_db_key_available);
    _IncrementLastKeyUsed();
    CoinEntryValue copy_value = value;
    std::memcpy(copy_value.key_parent, new_parent_key, UINT256_NUM_BYTES);
    copy_value.root_group = new_parent_value.root_group;
    std::pair<CoinEntryKey, CoinEntryValue> copy_entry = std::make_pair(copy_key, copy_value);
    return copy_entry;
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

CoinEntryValue CCoinsViewDB::_GetRootValue() const
{
    return _GetValueByKey(current_root_key);
}

CoinEntryValue CCoinsViewDB::_GetValueByKey(const uint256_t &key) const
{
    CoinEntryValue value = INVALID_ENTRY;
    db.Read(CoinEntryKey(key), value);
    return value;
}

CoinEntryValue CCoinsViewDB::_GetValueByOutpoint(const COutPoint &outpoint) const
{
    return _FindCoin(outpoint);
}

// in cashdrive the key for the coin is the same as the old system, the full outpoint hash.
// we should return false if the coin is not available to the current root.
// internally call HaveCoin to run the check
bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const
{
    READLOCK(cs_utxo);
    if (cashdrive_debug)
    {
        LOGA("Calling GetCoin in cashdrive \n");
    }
    CoinEntryValue res = _FindCoin(outpoint);
    if (cashdrive_debug)
    {
        LOGA("res.ToString() = %s \n", res.ToString().c_str());
    }
    if (res != INVALID_ENTRY)
    {
        coin = res.value;
        if (cashdrive_debug)
        {
            LOGA("GetCoin: returning true \n");
        }
        return true;
    }
    if (cashdrive_debug)
    {
        LOGA("GetCoin: returning false \n");
    }
    return false;
}

void CCoinsViewDB::_MakeNewRoot()
{
    CoinEntryValue current_root_value = _GetRootValue();
    current_root_value.root_group += 1;
    current_root_group = current_root_value.root_group;
    std::memcpy(current_root_key, next_db_key_available, UINT256_NUM_BYTES);
    _IncrementLastKeyUsed();
    db.Write(DB_ROOT_KEY, uint256(current_root_key));
    db.Write(DB_LAST_ROOT_KEY, uint256(current_root_key));
    // new roots start as copies of the previous root with an incremented root group
    db.Write(CoinEntryKey(current_root_key), current_root_value);
}

void CCoinsViewDB::_IncrementLastKeyUsed()
{
    _WriteLastKeyUsed();
    int32_t i = 0;
    uint32_t* pn = (uint32_t*)next_db_key_available;
    while (++pn[i] == 0 && i < 7)
    {
        i++;
    }
}

void CCoinsViewDB::_WriteLastKeyUsed()
{
    // convert to uint256 class for serialization
    db.Write(DB_LAST_KEY_USED, uint256(next_db_key_available));
}

static void sha256ab(const uint256_t &a, const uint256_t &b, uint256_t res)
{
    CSHA256 hasher;
    hasher.Write(a, 32);
    hasher.Write(b, 32);
    hasher.Finalize(res);
}

CoinEntryValue CCoinsViewDB::_UpdateFingerprint(const uint256_t &parent_key)
{

    CoinEntryValue parent_value;
    if (!db.Read(CoinEntryKey(parent_key), parent_value))
    {
        assert(false);
    }
    // root case check, root is only non leaf node where it is possible to only
    // have one child
    int nCase = 0;
    if (parent_value.key_bits == 0)
    {
        // if missing left child
        if (std::memcmp(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0 &&
            std::memcmp(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0)
        {
            nCase = 1;
        }
        // if missing right child
        else if (std::memcmp(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0 &&
            std::memcmp(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0)
        {
            nCase = 2;
        }
        else if (std::memcmp(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0 &&
            std::memcmp(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0)
        {
            nCase = 3;
        }
    }
    CoinEntryValue left_value;
    if (nCase != 1 && nCase != 3)
    {
        if (!db.Read(CoinEntryKey(parent_value.key_left), left_value))
        {
            assert(false);
        }
    }
    CoinEntryValue right_value;
    if (nCase != 2 && nCase != 3)
    {
        if (!db.Read(CoinEntryKey(parent_value.key_right), right_value))
        {
            assert(false);
        }
    }
    if (nCase == 0)
    {
        sha256ab(left_value.fingerprint, right_value.fingerprint, parent_value.fingerprint);
    }
    else if (nCase == 1) // only used in root node
    {
        sha256ab(INVALID_KEY, right_value.fingerprint, parent_value.fingerprint);
    }
    else if (nCase == 2) // only used in root node
    {
        sha256ab(left_value.fingerprint, INVALID_KEY, parent_value.fingerprint);
    }
    else if (nCase == 3) // only used in root node for an empty trie
    {
        sha256ab(INVALID_KEY, INVALID_KEY, parent_value.fingerprint);
    }
    db.Write(CoinEntryKey(parent_key), parent_value);
    return parent_value;
}


// use the find algorithm from bitwise_trie to go from current root to what should be outpoint
// in the trie if it exists
// see BitwiseTrie_find in bitwise_trie.c for original find algorithm
CoinEntryValue CCoinsViewDB::_FindCoin(const COutPoint &outpoint) const
{
    uint256_t key;
    outpoint.hash.GetRaw(key);
    if (cashdrive_debug)
    {
        LOGA("Find(): key = %s \n", uint256t_ToString(key).c_str());
    }
    // compare the key of the node being added against the existing nodes starting with the root
    CoinEntryValue next_value;
    uint256_t next_key;
    std::memcpy(next_key, current_root_key, UINT256_NUM_BYTES);
    while (std::memcmp(next_key, INVALID_KEY, UINT256_NUM_BYTES) != 0)
    {
        if (!db.Read(CoinEntryKey(next_key), next_value))
        {
            assert(false);
        }
        // special root case
        if (next_value.key_bits == 0)
        {
            if ((key[0] & BIN_10000000) == BIN_10000000)
            {
                // go right
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                if (cashdrive_debug)
                {
                    LOGA("Find(): root case, going right \n");
                }
                continue;
            }
            else
            {
                // go left
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                if (cashdrive_debug)
                {
                    LOGA("Find(): root case, going left \n");
                }
                continue;
            }
        }
        if (next_value.key_bits == 256)
        {
            if (std::memcmp(key, next_value.key, UINT256_NUM_BYTES) != 0)
            {
                // arrived at the place where the key should be but it was not found
                if (cashdrive_debug)
                {
                    LOGA("Find(): fail return 0 \n");
                }
                return INVALID_ENTRY;
            }
            else
            {
                if (cashdrive_debug)
                {
                    LOGA("Find(): returning next_value \n");
                }
                return next_value;
            }
        }
        if (cashdrive_debug)
        {
            LOGA("Find(): key = %s, next_value.key = %s, next_value.key_bits = %u \n", uint256t_ToString(key).c_str(), uint256t_ToString(next_value.key).c_str(), next_value.key_bits);
        }
        int res = _compare_key_bits(key, next_value.key, next_value.key_bits);
        if (res == 0)
        {
            // after the key bits interior node keys are all 0,
            // we only need to check the bit of new node key that is
            // interior node keybits + 1 to determine which way we go.
            // 0 si left, 1 is right
            const uint32_t byte_to_check = next_value.key_bits / 8;
            const uint32_t next_key_bits = next_value.key_bits % 8;
            uint8_t bit_to_check = BIN_10000000;
            if (next_key_bits == 0)
            {
                // intentionally do nothing
            }
            else if (next_key_bits == 1)
            {
                bit_to_check = BIN_01000000;
            }
            else if(next_key_bits == 2)
            {
                bit_to_check = BIN_00100000;
            }
            else if(next_key_bits == 3)
            {
                bit_to_check = BIN_00010000;
            }
            else if(next_key_bits == 4)
            {
                bit_to_check = BIN_00001000;
            }
            else if(next_key_bits == 5)
            {
                bit_to_check = BIN_00000100;
            }
            else if(next_key_bits == 6)
            {
                bit_to_check = BIN_00000010;
            }
            else if (next_key_bits == 7)
            {
                bit_to_check = BIN_00000001;
            }
            res = (key[byte_to_check] & bit_to_check);
            // the keybits in the key and next key were the same
            // check each branch of the next node
            if (res <= 0) // go left?
            {
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                if (cashdrive_debug)
                {
                    LOGA("Find(): res == 0, res <= 0, going left \n");
                }
                continue;
            }
            else // go right?
            {
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                if (cashdrive_debug)
                {
                    LOGA("Find(): res == 0, res > 0, going right \n");
                }
                continue;
            }
            if (cashdrive_debug)
            {
                LOGA("Find(): fail return 1 \n");
            }
            return INVALID_ENTRY;
        }
        else if (res < 0)
        {
            std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
            if (cashdrive_debug)
            {
                LOGA("Find(): res < 0, going left \n");
            }
            continue;
        }
        else // res > 0
        {
            std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
            if (cashdrive_debug)
            {
                LOGA("Find(): res > 0, going right \n");
            }
            continue;
        }
    }
    if (cashdrive_debug)
    {
        LOGA("Find(): fail return 2 \n");
    }
    return INVALID_ENTRY;
}


// Note about Mint and Spend
// it is required that any changes to a node in the trie be written to disk immediately
// to ensure that any future use of that node, which would read the data from disk, returns
// the most recent data

bool CCoinsViewDB::Mint(const COutPoint &outpoint, const Coin &coin)
{
    if (_FindCoin(outpoint) != INVALID_ENTRY)
    {
        // can not add an entry for a value that already exists
        if (cashdrive_debug)
        {
            LOGA("Mint(): FIND FAILURE \n");
        }
        return false;
    }
    // create the new entry we will be adding
    // key
    CoinEntryKey key(next_db_key_available);
    _IncrementLastKeyUsed();
    // value
    CoinEntryValue value;
    value.SetNull();
    outpoint.hash.GetRaw(value.key);
    // the key is also the fingerprint for a leaf node as a shortcut for calculating
    // the fingerprint of the parent node
    outpoint.hash.GetRaw(value.fingerprint);
    value.value = coin;
    value.key_bits = 256;
    bool isLeft = false;
    // compare the key of the node being added against the existing nodes starting with the root
    uint256_t parent_key;
    std::memcpy(parent_key, current_root_key, UINT256_NUM_BYTES);
    CoinEntryValue parent_value;
    if (!db.Read(CoinEntryKey(parent_key), parent_value))
    {
        // this is a critical error, if they key we are reading from is not
        // invalid, then the entry should not be missing
        assert(false);
    }
    uint256_t next_key;
    std::memcpy(next_key, current_root_key, UINT256_NUM_BYTES);
    CoinEntryValue next_value;
    while (std::memcmp(next_key, INVALID_KEY, UINT256_NUM_BYTES) != 0)
    {
        if (!db.Read(CoinEntryKey(next_key), next_value))
        {
            // this is a critical error, if they key we are reading from is not
            // invalid, then the entry should not be missing
            assert(false);
        }
        if (cashdrive_debug)
        {
            LOGA("MINT(): next_key: %s, next_value: %s \n", uint256t_ToString(next_value.key).c_str(), next_value.ToString().c_str());
        }
        // if next is a leaf node...
        if (next_value.key_bits == 256)
        {
            // create a new interior node for a parent and write it to the db
            std::pair<CoinEntryKey, CoinEntryValue> new_parent_node = _make_new_interior_node(parent_key, parent_value, next_key, next_value, value.key);
            // update values we are tracking
            std::memcpy(next_key, new_parent_node.first.key, UINT256_NUM_BYTES);
            next_value = new_parent_node.second;
            std::memcpy(parent_key, new_parent_node.second.key_parent, UINT256_NUM_BYTES);
            if (!db.Read(CoinEntryKey(parent_key), parent_value))
            {
                // this is a critical error, if they key we are reading from is not
                // invalid, then the entry should not be missing
                assert(false);
            }
            if (cashdrive_debug)
            {
                LOGA("Mint(): leaf node case, making new interior node and cycling \n");
            }
            continue;
        }
        if (next_value.key_bits == 0)
        {
            if (cashdrive_debug)
            {
                LOGA("Mint(): root case, value.key[0] = %u \n", value.key[0]);
            }
            if ((value.key[0] & BIN_10000000) == BIN_10000000)
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                isLeft = false;
                if (cashdrive_debug)
                {
                    LOGA("Mint(): root case, going right \n");
                }
                continue;
            }
            else
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                isLeft = true;
                if (cashdrive_debug)
                {
                    LOGA("Mint(): root case, going left \n");
                }
                continue;
            }
        }
        // next is an interior node
        int32_t res = _compare_key_bits(value.key, next_value.key, next_value.key_bits);
        if (res != 0) // the keybits in the key and next key were NOT the same
        {
            if (cashdrive_debug)
            {
                LOGA("Mint(): res != 0 \n");
            }
            // create a new interior node for a parent and write it to the db
            std::pair<CoinEntryKey, CoinEntryValue> new_parent_node = _make_new_interior_node(parent_key, parent_value, next_key, next_value, value.key);
            // update values we are tracking
            std::memcpy(next_key, new_parent_node.first.key, UINT256_NUM_BYTES);
            next_value = new_parent_node.second;
            std::memcpy(parent_key, next_value.key_parent, UINT256_NUM_BYTES);
            if (!db.Read(CoinEntryKey(parent_key), parent_value))
            {
                // this is a critical error, if they key we are reading from is not
                // invalid, then the entry should not be missing
                assert(false);
            }
            if (cashdrive_debug)
            {
                LOGA("Mint(): made new interior node, cycling \n");
            }
        }
        else // (res == 0) // the keybits in the key and next key were the same
        {
            if (cashdrive_debug)
            {
                LOGA("Mint(): res == 0\n");
            }

            // whichever branch we go down, we need to be in the same root group
            if (next_value.root_group != current_root_group)
            {
                // the parent will always be in the correct root group
                std::pair<CoinEntryKey, CoinEntryValue> entry_copy = _copy_entry_with_new_parent(next_value, parent_key, parent_value);
                if (isLeft == true)
                {
                    std::memcpy(parent_value.key_left, entry_copy.first.key, UINT256_NUM_BYTES);
                }
                else
                {
                    std::memcpy(parent_value.key_right, entry_copy.first.key, UINT256_NUM_BYTES);
                }
                CDBBatch batch(db);
                batch.Write(entry_copy.first, entry_copy.second);
                batch.Write(CoinEntryKey(parent_key), parent_value);
                db.WriteBatch(batch);
                std::memcpy(next_key, entry_copy.first.key, UINT256_NUM_BYTES);
                next_value = entry_copy.second;
                if (cashdrive_debug)
                {
                    LOGA("Mint(): copied entry with new parent\n");
                }
                assert(next_value.root_group == current_root_group);
            }

            // after the key bits interior node keys are all 0,
            // we only need to check the bit of new node key that is
            // interior node keybits + 1 to determine which way we go.
            // 0 si left, 1 is right
            uint32_t byte_to_check = next_value.key_bits / 8;
            const uint32_t next_key_bits = next_value.key_bits % 8;
            uint8_t bit_to_check = BIN_10000000;
            if (next_key_bits == 0)
            {
                // intentionally do nothing
            }
            else if (next_key_bits == 1)
            {
                bit_to_check = BIN_01000000;
            }
            else if(next_key_bits == 2)
            {
                bit_to_check = BIN_00100000;
            }
            else if(next_key_bits == 3)
            {
                bit_to_check = BIN_00010000;
            }
            else if(next_key_bits == 4)
            {
                bit_to_check = BIN_00001000;
            }
            else if(next_key_bits == 5)
            {
                bit_to_check = BIN_00000100;
            }
            else if(next_key_bits == 6)
            {
                bit_to_check = BIN_00000010;
            }
            else if (next_key_bits == 7)
            {
                bit_to_check = BIN_00000001;
            }
            res = (value.key[byte_to_check] & bit_to_check);
            if (res <= 0)
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                isLeft = true;
                if (cashdrive_debug)
                {
                    LOGA("Mint(): res == 0, res <= 0, case 1, going left\n");
                }
            }
            else
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                isLeft = false;
                if (cashdrive_debug)
                {
                    LOGA("Mint(): res == 0, res > 0, case 1, going right\n");
                }
            }
            continue;
        }
    }
    // if we are here, next is null. and we need to add data to parent
    if (isLeft)
    {
        assert(std::memcmp(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES) == 0);
        std::memcpy(parent_value.key_left, key.key, UINT256_NUM_BYTES);
        if (cashdrive_debug)
        {
            LOGA("Mint(): added new node on parent left \n");
        }
    }
    else // right
    {
        assert(std::memcmp(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES) == 0);
        std::memcpy(parent_value.key_right, key.key, UINT256_NUM_BYTES);
        if (cashdrive_debug)
        {
            LOGA("Mint(): added new node on parent right \n");
        }
    }
    CDBBatch batch(db);
    // parent has been updated, write the changges
    batch.Write(CoinEntryKey(parent_key), parent_value);
    // populate the value parent key with the parent key
    std::memcpy(value.key_parent, parent_key, UINT256_NUM_BYTES);
    // leaf nodes do not have a relevant root group
    value.root_group = parent_value.root_group;
    // value has been created, write it to the db
    batch.Write(key, value);
    db.WriteBatch(batch);
    // update fingerprint
    while (std::memcmp(parent_key, INVALID_KEY, UINT256_NUM_BYTES) != 0)
    {
        parent_value = _UpdateFingerprint(parent_key);
        assert(value.root_group == parent_value.root_group);
        std::memcpy(parent_key, parent_value.key_parent, UINT256_NUM_BYTES);
        value = parent_value;
    }
    return true;
}

bool CCoinsViewDB::Spend(const COutPoint &outpoint)
{
    if (_FindCoin(outpoint) == INVALID_ENTRY)
    {
        // nothing to spend, return false
        // TODO : consider returning true because the state of the trie is
        // the desired end state of the spend
        // could also return the number of elements removed (0 or 1)
        if (cashdrive_debug)
        {
            LOGA("Spend(): FIND FAILURE \n");
        }
        // TODO : return true but dbgassert for testing to catch failures
        return false;
    }
    uint256_t outpoint_key;
    outpoint.hash.GetRaw(outpoint_key);
    // run the find algorithm again but update the nodes we touch
    bool isLeft = false;
    // compare the key of the node being added against the existing nodes starting with the root
    uint256_t parent_key;
    std::memcpy(parent_key, current_root_key, UINT256_NUM_BYTES);
    CoinEntryValue parent_value;
    if (!db.Read(CoinEntryKey(parent_key), parent_value))
    {
        assert(false);
    }
    uint256_t next_key;
    std::memcpy(next_key, current_root_key, UINT256_NUM_BYTES);
    CoinEntryValue next_value;
    bool removed = false;
    int res;
    while (std::memcmp(next_key, INVALID_KEY, UINT256_NUM_BYTES) != 0)
    {
        if (!db.Read(CoinEntryKey(next_key), next_value))
        {
            // this is a critical error, if they key we are reading from is not
            // invalid, then the entry should not be missing
            assert(false);
        }
        // is next the node we are looking for?
        if (next_value.key_bits == 256)
        {
            // this is the node we are looking for, disconnect it from its parent in
            // the current root group
            if (isLeft)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): spending left \n");
                }
                std::memcpy(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES);
            }
            else
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): spending right \n");
                }
                std::memcpy(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES);
            }
            if (cashdrive_debug)
            {
                LOGA("Spend(): removed set to true \n");
            }
            removed = true;
            // parent was updated, write the changes to the DB
            db.Write(CoinEntryKey(parent_key), parent_value);
            break;
        }
        // update every node we touch if they are not in the current root_group
        if (next_value.root_group != current_root_group)
        {
            // the parent will always be in the correct root group
            std::pair<CoinEntryKey, CoinEntryValue> entry_copy = _copy_entry_with_new_parent(next_value, parent_key, parent_value);
            if (isLeft == true)
            {
                std::memcpy(parent_value.key_left, entry_copy.first.key, UINT256_NUM_BYTES);
            }
            else
            {
                std::memcpy(parent_value.key_right, entry_copy.first.key, UINT256_NUM_BYTES);
            }
            CDBBatch batch(db);
            batch.Write(entry_copy.first, entry_copy.second);
            batch.Write(CoinEntryKey(parent_key), parent_value);
            db.WriteBatch(batch);
            std::memcpy(next_key, entry_copy.first.key, UINT256_NUM_BYTES);
            next_value = entry_copy.second;
            assert(next_value.root_group == current_root_group);
        }
        // special root case
        if (next_value.key_bits == 0)
        {
            if ((outpoint_key[0] & BIN_10000000) == BIN_10000000)
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                isLeft = false;
                if (cashdrive_debug)
                {
                    LOGA("Spend(): root case, going right \n");
                }
                continue;
            }
            else
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                isLeft = true;
                if (cashdrive_debug)
                {
                    LOGA("Spend(): root case, going left \n");
                }
                continue;
            }
        }
        res = _compare_key_bits(outpoint_key, next_value.key, next_value.key_bits);
        if (res == 0)
        {
            if (cashdrive_debug)
            {
                LOGA("Spend(): res == 0 \n");
            }
            // after the key bits interior node keys are all 0,
            // we only need to check the bit of new node key that is
            // interior node keybits + 1 to determine which way we go.
            // 0 si left, 1 is right
            const uint32_t byte_to_check = next_value.key_bits / 8;
            const uint32_t next_key_bits = next_value.key_bits % 8;
            uint8_t bit_to_check = BIN_10000000;
            if (next_key_bits == 0)
            {
                // intentionally do nothing
            }
            else if (next_key_bits == 1)
            {
                bit_to_check = BIN_01000000;
            }
            else if(next_key_bits == 2)
            {
                bit_to_check = BIN_00100000;
            }
            else if(next_key_bits == 3)
            {
                bit_to_check = BIN_00010000;
            }
            else if(next_key_bits == 4)
            {
                bit_to_check = BIN_00001000;
            }
            else if(next_key_bits == 5)
            {
                bit_to_check = BIN_00000100;
            }
            else if(next_key_bits == 6)
            {
                bit_to_check = BIN_00000010;
            }
            else if (next_key_bits == 7)
            {
                bit_to_check = BIN_00000001;
            }
            res = (outpoint_key[byte_to_check] & bit_to_check);
            // the keybits in the key and next key were the same
            // check each branch of the next node
            if (res <= 0) // go left?
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
                isLeft = true;
                if (cashdrive_debug)
                {
                    LOGA("Spend(): res == 0, res <= 0, going left \n");
                }
                continue;
            }
            else // go right?
            {
                std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
                parent_value = next_value;
                std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
                isLeft = false;
                if (cashdrive_debug)
                {
                    LOGA("Spend(): res == 0, res > 0, going right \n");
                }
                continue;
            }
            break;
        }
        else if (res < 0)
        {
            if (cashdrive_debug)
            {
                LOGA("Spend(): res < 0, going left \n");
            }
            std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
            parent_value = next_value;
            std::memcpy(next_key, next_value.key_left, UINT256_NUM_BYTES);
            isLeft = true;
            continue;
        }
        else // res > 0
        {
            if (cashdrive_debug)
            {
                LOGA("Spend(): res > 0, going right \n");
            }
            std::memcpy(parent_key, next_key, UINT256_NUM_BYTES);
            parent_value = next_value;
            std::memcpy(next_key, next_value.key_right, UINT256_NUM_BYTES);
            isLeft = false;
            continue;
        }
    }
    // if we removed something go back up to the root and trim intermediate nodes with less than 2 children
    if (removed == true)
    {
        if (cashdrive_debug)
        {
            LOGA("Spend(): removed == true \n");
        }
        // create a NULL parent_parent
        uint256_t parent_parent_key;
        std::memcpy(parent_parent_key, INVALID_KEY, UINT256_NUM_BYTES);
        CoinEntryValue parent_parent_value;
        parent_parent_value.SetNull();
        while (std::memcmp(parent_key, INVALID_KEY, UINT256_NUM_BYTES) != 0)
        {
            if (!db.Read(CoinEntryKey(parent_key), parent_value))
            {
                // this is a critical error, if they key we are reading from is not
                // invalid, then the entry should not be missing
                assert(false);
            }
            std::memcpy(parent_parent_key, parent_value.key_parent, UINT256_NUM_BYTES);
            if (std::memcmp(parent_parent_key, INVALID_KEY, UINT256_NUM_BYTES) == 0)
            {
                // only root has a null parent
                // break on root, we can not trim the root
                if (cashdrive_debug)
                {
                    LOGA("Spend(): back up to root, breaking \n");
                    LOGA("Spend(): Updating fingerprint in root case \n");
                }
                // we must update the fingerprint for the root before breaking
                parent_value = _UpdateFingerprint(parent_key);
                break;
            }
            if (!db.Read(CoinEntryKey(parent_parent_key), parent_parent_value))
            {
                // this is a critical error, if they key we are reading from is not
                // invalid, then the entry should not be missing
                assert(false);
            }
            assert(parent_value.root_group == parent_parent_value.root_group);
            int32_t children = 0;
            if (std::memcmp(parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES) != 0)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): children + 1 \n");
                }
                children = children + 1;
            }
            if (std::memcmp(parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES) != 0)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): children + 2 \n");
                }
                children = children + 2;
            }
            if (children == 3)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): has 3 children, breaking \n");
                }
                // has both children, we are done
                // we intentionally do nothing to continue looping to
                // update the fingerprint all the way up to the root
            }
            else if (children == 0)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): has 0 children \n");
                }
                if (std::memcmp(parent_parent_value.key_left, parent_key, UINT256_NUM_BYTES) == 0)
                {
                    std::memcpy(parent_parent_value.key_left, INVALID_KEY, UINT256_NUM_BYTES);
                }
                else // parent_parent->right == parent
                {
                    std::memcpy(parent_parent_value.key_right, INVALID_KEY, UINT256_NUM_BYTES);
                }
                // parent_parent_value was updated, write the changes to the db
                db.Write(CoinEntryKey(parent_parent_key), parent_parent_value);
            }
            else if (children == 1)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): has 1 child \n");
                }
                // left child is not null but right is, condense
                if (std::memcmp(parent_parent_value.key_left, parent_key, UINT256_NUM_BYTES) == 0)
                {
                    if (cashdrive_debug)
                    {
                        LOGA("Spend(): has 1 child, case 1 \n");
                    }
                    std::memcpy(parent_parent_value.key_left, parent_value.key_left, UINT256_NUM_BYTES);
                    CoinEntryValue parent_left_value;
                    if (!db.Read(CoinEntryKey(parent_value.key_left), parent_left_value))
                    {
                        // this is a critical error, if they key we are reading from is not
                        // invalid, then the entry should not be missing
                        assert(false);
                    }
                    std::memcpy(parent_left_value.key_parent, parent_parent_key, UINT256_NUM_BYTES);
                    CDBBatch batch(db);
                    // parent_left_value was updated, write the changes to the db
                    batch.Write(CoinEntryKey(parent_value.key_left), parent_left_value);
                    // parent_parent_value.key_left was updated, wrtie the changes to the db
                    batch.Write(CoinEntryKey(parent_parent_key), parent_parent_value);
                    db.WriteBatch(batch);
                }
                else // parent_parent->right == parent
                {
                    if (cashdrive_debug)
                    {
                        LOGA("Spend(): has 1 child, case 2 \n");
                    }
                    std::memcpy(parent_parent_value.key_right, parent_value.key_left, UINT256_NUM_BYTES);
                    CoinEntryValue parent_left_value;
                    if (!db.Read(CoinEntryKey(parent_value.key_left), parent_left_value))
                    {
                        // this is a critical error, if they key we are reading from is not
                        // invalid, then the entry should not be missing
                        assert(false);
                    }
                    std::memcpy(parent_left_value.key_parent, parent_parent_key, UINT256_NUM_BYTES);
                    CDBBatch batch(db);
                    // parent_left_value was updated, write the changes to the db
                    batch.Write(CoinEntryKey(parent_value.key_left), parent_left_value);
                    // parent_parent_value.key_right was updated, wrtie the changes to the db
                    batch.Write(CoinEntryKey(parent_parent_key), parent_parent_value);
                    db.WriteBatch(batch);
                }
            }
            else if (children == 2)
            {
                if (cashdrive_debug)
                {
                    LOGA("Spend(): has 2 children \n");
                }
                // right child is not null but left is, condense
                if (std::memcmp(parent_parent_value.key_left, parent_key, UINT256_NUM_BYTES) == 0)
                {
                    std::memcpy(parent_parent_value.key_left, parent_value.key_right, UINT256_NUM_BYTES);
                    CoinEntryValue parent_right_value;
                    if (!db.Read(CoinEntryKey(parent_value.key_right), parent_right_value))
                    {
                        // this is a critical error, if they key we are reading from is not
                        // invalid, then the entry should not be missing
                        assert(false);
                    }
                    std::memcpy(parent_right_value.key_parent, parent_parent_key, UINT256_NUM_BYTES);
                    CDBBatch batch(db);
                    // parent_right_value was updated, write the changes to the db
                    batch.Write(CoinEntryKey(parent_value.key_right), parent_right_value);
                    // parent_parent_value.key_left was updated, wrtie the changes to the db
                    batch.Write(CoinEntryKey(parent_parent_key), parent_parent_value);
                    db.WriteBatch(batch);
                }
                else // parent_parent->right == parent
                {
                    std::memcpy(parent_parent_value.key_right, parent_value.key_right, UINT256_NUM_BYTES);
                    CoinEntryValue parent_right_value;
                    if (!db.Read(CoinEntryKey(parent_value.key_right), parent_right_value))
                    {
                        // this is a critical error, if they key we are reading from is not
                        // invalid, then the entry should not be missing
                        assert(false);
                    }
                    std::memcpy(parent_right_value.key_parent, parent_parent_key, UINT256_NUM_BYTES);
                    CDBBatch batch(db);
                    // parent_right_value was updated, write the changes to the db
                    batch.Write(CoinEntryKey(parent_value.key_right), parent_right_value);
                    // parent_parent_value.key_right was updated, wrtie the changes to the db
                    batch.Write(CoinEntryKey(parent_parent_key), parent_parent_value);
                    db.WriteBatch(batch);
                }
            }
            std::memcpy(parent_key, parent_parent_key, UINT256_NUM_BYTES);
            if (cashdrive_debug)
            {
                LOGA("Spend(): Updating fingerprint in loop \n");
            }
            parent_value = _UpdateFingerprint(parent_key);
        }
    }
    return removed;
}

struct TrieStack
{
    std::pair<CoinEntryKey, CoinEntryValue> node;
    struct TrieStack* next; // next TrimStack node
};
typedef struct TrieStack TrieStack;

static bool _TrieStack_empty(TrieStack* top)
{
    return top == NULL;
}

static void _TrieStack_push(TrieStack** top, std::pair<CoinEntryKey, CoinEntryValue> node)
{
    TrieStack* new_layer = (TrieStack*) malloc(sizeof(TrieStack));
    if (new_layer == NULL)
    {
        assert(false);
    }
    new_layer->node = node;
    new_layer->next = (*top);
    (*top) = new_layer;
}

static std::pair<CoinEntryKey, CoinEntryValue> _TrieStack_pop(TrieStack** top)
{
    assert(_TrieStack_empty(*top) == false);
    TrieStack* tmp = *top;
    std::pair<CoinEntryKey, CoinEntryValue> res = tmp->node;
    *top = tmp->next;
    free(tmp);
    return res;
}

uint256 CCoinsViewDB::GetFingerprint()
{
    return uint256(_GetRootValue().fingerprint);
}

void CCoinsViewDB::_debug_print_trie()
{
    std::pair<CoinEntryKey, CoinEntryValue> invalid_node = std::make_pair(CoinEntryKey(INVALID_KEY), INVALID_ENTRY);
    LOGA("\n\n\n PRINT TRIE BEGIN \n");
    TrieStack* stack = NULL;
    // traverse the entire trie's current root, print key values and keybits
    CoinEntryValue root_value = _GetRootValue();
    // LOGA("root_value = %s \n", root_value.ToString().c_str());
    std::pair<CoinEntryKey, CoinEntryValue> node = std::make_pair(CoinEntryKey(current_root_key), root_value);
    while (true)
    {
        if (node.second != INVALID_ENTRY)
        {
            _TrieStack_push(&stack, node);
            CoinEntryValue left_value;
            //LOGA("left_key = %s \n", uint256t_ToString(node.second.key_left));
            if (!db.Read(CoinEntryKey(node.second.key_left), left_value))
            {
                LOGA("node set to invalid (1) \n");
                node = invalid_node;
            }
            else
            {
                LOGA("going left \n");
                node = std::make_pair(CoinEntryKey(node.second.key_left), std::move(left_value));
                //LOGA("node now has key %s, value %s \n", uint256t_ToString(node.first.key).c_str(), node.second.ToString().c_str());
            }
        }
        else
        {
            if (_TrieStack_empty(stack) == false)
            {
                LOGA("going up \n");
                node = _TrieStack_pop(&stack);
                if (node.second.key_bits == 256)
                {
                    //LOGA(">>>>node has key %s, value %s \n", uint256t_ToString(node.first.key).c_str(), node.second.ToString().c_str());
                    LOGA(">>>>node has key %s\n", uint256t_ToString(node.second.key).c_str());
                }
                CoinEntryValue right_value;
                //LOGA("right_key = %s \n", uint256t_ToString(node.second.key_right));
                if (!db.Read(CoinEntryKey(node.second.key_right), right_value))
                {
                    LOGA("node set to invalid (2) \n");
                    node = invalid_node;
                }
                else
                {
                    LOGA("going right \n");
                    node = std::make_pair(CoinEntryKey(node.second.key_right), std::move(right_value));
                    //LOGA("node now has key %s, value %s \n", uint256t_ToString(node.first.key).c_str(), node.second.ToString().c_str());
                }
            }
            else
            {
                break;
                LOGA("PRINT TRIE BREAK \n\n\n");
            }
        }
    }
    LOGA("PRINT TRIE END \n\n\n");
}

bool CCoinsViewDB::_HaveCoin(const COutPoint &outpoint) const
{
    return (_FindCoin(outpoint) != INVALID_ENTRY);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const
{
    READLOCK(cs_utxo);
    return _HaveCoin(outpoint);
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
    size_t count = 0;
    size_t changed = 0;
    size_t nBatchWrites = 0;
    size_t spent_coins = 0;

    LOG(COINDB, "starting committing process\n");
    // typedef std::unordered_map<COutPoint, CCoinsCacheEntry, SaltedOutpointHasher> CCoinsMap;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();)
    {
        if (it->second.flags & CCoinsCacheEntry::DIRTY)
        {
            size_t nUsage = it->second.coin.DynamicMemoryUsage();
            if (it->second.coin.IsSpent())
            {
                Spend(it->first);
                spent_coins++;

                // Update the usage of the child cache before deleting the entry in the child cache
                nChildCachedCoinsUsage -= nUsage;
                it = mapCoins.erase(it);
            }
            else
            {
                Mint(it->first, it->second.coin);

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
        }
        else
        {
            it++;
        }
        count++;
    }
    if (!hashBlock.IsNull())
    {
        _WriteBestBlock(hashBlock);
    }
    LOG(COINDB,
        "Committing %u changed transactions (out of %u) to coin database with %u batch writes and %u spent coins...\n",
        (unsigned int)changed, (unsigned int)count, (unsigned int)nBatchWrites, (unsigned int)spent_coins);

    return true;
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
        CoinEntryKey entry(i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key_prefix;
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
