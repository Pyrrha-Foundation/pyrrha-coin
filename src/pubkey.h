// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_PUBKEY_H
#define NEXA_PUBKEY_H

#include "hashwrapper.h"
#include "keyid.h"
#include "serialize.h"
#include "tweak.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>

extern CTweak<bool> falconTweak;

enum
{
    BIP32_EXTKEY_SIZE = 74
};

typedef uint256 ChainCode;

/** An encapsulated secp256k1 public key. */
class CPubKey
{
public:
    /**
     * secp256k1:
     */
    static constexpr unsigned int PUBLIC_KEY_SIZE = 65;
    static constexpr unsigned int COMPRESSED_PUBLIC_KEY_SIZE = 33;
    static constexpr unsigned int SIGNATURE_SIZE = 72;
    static constexpr unsigned int COMPACT_SIGNATURE_SIZE = 65;
    static constexpr unsigned int PUBLIC_KEY_HASH160_SIZE = 20;
    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(PUBLIC_KEY_SIZE >= COMPRESSED_PUBLIC_KEY_SIZE,
        "COMPRESSED_PUBLIC_KEY_SIZE is larger than PUBLIC_KEY_SIZE");

    /**
     * falcon:
     */
    static constexpr unsigned int FALCON_PUBLIC_KEY_SIZE = 897;
    static constexpr unsigned int FALCON_COMPRESSED_PUBLIC_KEY_SIZE = 897;
    static constexpr unsigned int FALCON_SIGNATURE_SIZE = 666;
    static constexpr unsigned int FALCON_COMPACT_SIGNATURE_SIZE = 666;

    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(FALCON_PUBLIC_KEY_SIZE >= FALCON_COMPRESSED_PUBLIC_KEY_SIZE,
        "FALCON_COMPRESSED_PUBLIC_KEY_SIZE is larger than FALCON_PUBLIC_KEY_SIZE");

private:
    //! Whether this is a falcon key or not
    bool fFalcon;

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vch[PUBLIC_KEY_SIZE];
    unsigned char vch_falcon[FALCON_PUBLIC_KEY_SIZE];


    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        // ECC
        if (chHeader == 2 || chHeader == 3)
            return COMPRESSED_PUBLIC_KEY_SIZE;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return PUBLIC_KEY_SIZE;

        // falcon
        if (chHeader == 9)
            return FALCON_PUBLIC_KEY_SIZE;

        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        // Falcon
        {
            memset(vch_falcon, 0, FALCON_PUBLIC_KEY_SIZE); // don't expose arbitrary stack bytes
            vch_falcon[0] = 0xFF;
        }
        // ECC
        {
            memset(vch, 0, PUBLIC_KEY_SIZE); // don't expose arbitrary stack bytes
            vch[0] = 0xFF;
        }
    }

public:
    bool static ValidSize(const std::vector<uint8_t> &vch) { return vch.size() > 0 && GetLen(vch[0]) == vch.size(); }
    //! Construct an invalid public key.
    CPubKey()
    {
        fFalcon = false;
        Invalidate();
    }

    template <typename T>
    void SetFalcon(const T pbegin, const T pend)
    {
        memcpy(vch_falcon, (unsigned char *)&pbegin[0], FALCON_PUBLIC_KEY_SIZE);
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        // set pubkey
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char *)&pbegin[0], len);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        // set fFalcon flag
        if ((pend - pbegin == FALCON_PUBLIC_KEY_SIZE) && (GetLen(pbegin[0]) == FALCON_PUBLIC_KEY_SIZE))
        {
            fFalcon = true;
            SetFalcon(pbegin, pend);
        }
        else
        {
            fFalcon = false;
            Set(pbegin, pend);
        }
    }

    //! Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char> &_vch)
    {
        if ((_vch.end() - _vch.begin() == FALCON_PUBLIC_KEY_SIZE) && (GetLen(_vch[0]) == FALCON_PUBLIC_KEY_SIZE))
        {
            fFalcon = true;
            SetFalcon(_vch.begin(), _vch.end());
        }
        else
        {
            fFalcon = false;
            Set(_vch.begin(), _vch.end());
        }
    }
    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const
    {
        if (fFalcon)
            return GetLen(vch_falcon[0]);
        else
            return GetLen(vch[0]);
    }
    const unsigned char *data() const
    {
        if (fFalcon)
            return vch_falcon;
        else
            return vch;
    }
    const unsigned char *begin() const
    {
        if (fFalcon)
            return vch_falcon;
        else
            return vch;
    }
    const unsigned char *end() const
    {
        if (fFalcon)
            return vch_falcon + size();
        else
            return vch + size();
    }
    const unsigned char &operator[](unsigned int pos) const
    {
        if (fFalcon)
            return vch_falcon[pos];
        else
            return vch[pos];
    }
    //! Comparator implementation.
    friend bool operator==(const CPubKey &a, const CPubKey &b)
    {
        if (a.fFalcon || b.fFalcon)
            return a.fFalcon == b.fFalcon && a.vch_falcon[0] == b.vch_falcon[0] &&
                   memcmp(a.vch_falcon, b.vch_falcon, a.size()) == 0;
        else
            return a.fFalcon == b.fFalcon && a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey &a, const CPubKey &b) { return !(a == b); }
    friend bool operator<(const CPubKey &a, const CPubKey &b)
    {
        if (a.fFalcon != b.fFalcon)
            return false;

        if (a.fFalcon || b.fFalcon)
            return a.vch_falcon[0] < b.vch_falcon[0] ||
                   (a.vch_falcon[0] == b.vch_falcon[0] && memcmp(a.vch_falcon, b.vch_falcon, a.size()) < 0);
        else
            return a.vch[0] < b.vch[0] || (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    //! Implement serialization, as if this was a byte vector.
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        if (fFalcon)
        {
            unsigned int len = size();
            ::WriteCompactSize(s, len);
            s.write((char *)vch_falcon, len);
        }
        else
        {
            unsigned int len = size();
            ::WriteCompactSize(s, len);
            s.write((char *)vch, len);
        }
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        unsigned int len = ::ReadCompactSize(s);
        if (len <= PUBLIC_KEY_SIZE)
        {
            fFalcon = false;
            s.read((char *)vch, len);
        }
        else if (len <= FALCON_PUBLIC_KEY_SIZE)
        {
            fFalcon = true;
            s.read((char *)vch_falcon, len);
        }
        else
        {
            // invalid pubkey, skip available data
            char dummy;
            while (len--)
                s.read(&dummy, 1);
            Invalidate();
        }
    }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        if (fFalcon)
            return CKeyID(Hash160(vch_falcon, vch_falcon + size()));
        else
            return CKeyID(Hash160(vch, vch + size()));
    }
    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        if (fFalcon)
            return Hash(vch_falcon, vch_falcon + size());
        else
            return Hash(vch, vch + size());
    }

    std::string GetHex() const;

    //! Check whether this is a falcon key.
    bool IsFalcon() const { return fFalcon; }
    bool IsValid() const { return size() > 0; }
    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const
    {
        if (fFalcon)
            return size() == FALCON_COMPRESSED_PUBLIC_KEY_SIZE;
        else
            return size() == COMPRESSED_PUBLIC_KEY_SIZE;
    }
    /**
     * Verify a DER-serialized ECDSA signature (~72 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    bool VerifyECDSA(const uint256 &hash, const std::vector<uint8_t> &vchSig) const;

    /**
     * Verify a Schnorr signature (=64 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    bool VerifySchnorr(const uint256 &hash, const std::vector<uint8_t> &vchSig) const;

    /**
     * Verify a falcon512 signature.
     * If this public key is not fully valid, the return value will be false.
     */
    bool VerifyFalcon(const uint256 &hash, const std::vector<uint8_t> &vchSig) const;

    /**
     * Check whether a DER-serialized ECDSA signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char> &vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256 &hash, const std::vector<uint8_t> &vchSig);

    //! Turn this public key into an uncompressed public key.
    bool Decompress();

    //! Derive BIP32 child pubkey.
    bool Derive(CPubKey &pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode &cc) const;
};

struct CExtPubKey
{
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CPubKey pubkey;

    friend bool operator==(const CExtPubKey &a, const CExtPubKey &b)
    {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 &&
               a.nChild == b.nChild && a.chaincode == b.chaincode && a.pubkey == b.pubkey;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtPubKey &out, unsigned int nChild) const;

    void Serialize(CSizeComputer &s) const
    {
        // Optimized implementation for ::GetSerializeSize that avoids copying.
        s.seek(BIP32_EXTKEY_SIZE + 1); // add one byte for the size (compact int)
    }
    template <typename Stream>
    void Serialize(Stream &s) const
    {
        unsigned int len = BIP32_EXTKEY_SIZE;
        ::WriteCompactSize(s, len);
        unsigned char code[BIP32_EXTKEY_SIZE];
        Encode(code);
        s.write((const char *)&code[0], len);
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        unsigned int len = ::ReadCompactSize(s);
        unsigned char code[BIP32_EXTKEY_SIZE];
        if (len != BIP32_EXTKEY_SIZE)
            throw std::runtime_error("Invalid extended key size\n");
        s.read((char *)&code[0], len);
        Decode(code);
    }
};

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

#endif // NEXA_PUBKEY_H
