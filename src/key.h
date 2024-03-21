// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_KEY_H
#define NEXA_KEY_H

#include "pubkey.h"
#include "serialize.h"
#include "support/allocators/secure.h"
#include "tweak.h"
#include "uint256.h"

#include <stdexcept>
#include <vector>

extern const uint32_t BIP32_HARDENED_KEY_LIMIT;
extern CTweak<bool> falconTweak;

/**
 * secure_allocator is defined in allocators.h
 * CPrivKey is a serialized private key, with all parameters included (PRIVATE_KEY_SIZE bytes)
 */
typedef std::vector<unsigned char, secure_allocator<unsigned char> > CPrivKey;

/** An encapsulated secp256k1 private key. */
class CKey
{
public:
    /**
     * secp256k1:
     */
    static const unsigned int PRIVATE_KEY_SIZE = 279;
    static const unsigned int COMPRESSED_PRIVATE_KEY_SIZE = 214;
    /**
     * see www.keylength.com
     * script supports up to 75 for single byte push
     */
    static_assert(PRIVATE_KEY_SIZE >= COMPRESSED_PRIVATE_KEY_SIZE,
        "COMPRESSED_PRIVATE_KEY_SIZE is larger than PRIVATE_KEY_SIZE");

    /**
     * falcon:
     */
    static const unsigned int FALCON_PRIVATE_KEY_SIZE = 1281;
    static const unsigned int FALCON_COMPRESSED_PRIVATE_KEY_SIZE = 1281;
    static const unsigned int FALCON_PUBKEY_SIZE = 897;
    static const unsigned int FALCON_SIGN_SIZE = 666;
    static_assert(FALCON_PRIVATE_KEY_SIZE >= FALCON_COMPRESSED_PRIVATE_KEY_SIZE,
        "FALCON_COMPRESSED_PRIVATE_KEY_SIZE is larger than FALCON_PRIVATE_KEY_SIZE");

private:
    //! Whether this is a falcon key or not
    bool fFalcon;

    //! Whether this private key is valid. We check for correctness when modifying the key
    //! data, so fValid should always correspond to the actual state.
    bool fValid;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;

    //! The actual byte data for a standard key
    unsigned char vch[32];

    //! The actual byte data for a falcon key
    std::vector<unsigned char, secure_allocator<unsigned char> > keydata;
    std::vector<unsigned char, secure_allocator<unsigned char> > pubkeydata;


    //! Check whether the 32-byte array pointed to be vch is valid keydata.
    bool Check(const unsigned char *_vch);

public:
    //! Construct an invalid private key.
    CKey() : fFalcon(false), fValid(false), fCompressed(false)
    {
        // For Falcon Keys
        {
            keydata.resize(FALCON_PRIVATE_KEY_SIZE);
            pubkeydata.resize(FALCON_PUBKEY_SIZE);
        }
        // For ECC keys
        {
            LockObject(vch);
        }
    }
    //! Copy constructor. This is necessary because of memlocking.
    CKey(const CKey &secret) : fFalcon(secret.fFalcon), fValid(secret.fValid), fCompressed(secret.fCompressed)
    {
        if (fFalcon)
        {
            keydata = secret.keydata;
            pubkeydata = secret.pubkeydata;
        }
        else
        {
            LockObject(vch);
            memcpy(vch, secret.vch, sizeof(vch));
        }
    }
    CKey &operator=(const CKey &secret)
    {
        fFalcon = secret.fFalcon;
        fValid = secret.fValid;
        fCompressed = secret.fCompressed;

        if (fFalcon)
        {
            keydata = secret.keydata;
            pubkeydata = secret.pubkeydata;
        }
        else
        {
            LockObject(vch);
            memcpy(vch, secret.vch, sizeof(vch));
        }

        return *this;
    }

    //! Destructor (again necessary because of memlocking).
    ~CKey()
    {
        if (!fFalcon)
        {
            UnlockObject(vch);
        }
    }
    friend bool operator==(const CKey &a, const CKey &b)
    {
        if (a.fFalcon || b.fFalcon)
        {
            return a.fFalcon == b.fFalcon && a.fCompressed == b.fCompressed && a.size() == b.size() &&
                   memcmp(&a.keydata, &b.keydata, a.size()) == 0;
        }
        else
        {
            return a.fFalcon == b.fFalcon && a.fCompressed == b.fCompressed && a.size() == b.size() &&
                   memcmp(&a.vch[0], &b.vch[0], a.size()) == 0;
        }
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, bool fCompressedIn)
    {
        fFalcon = ((size_t)(pend - pbegin) >= keydata.size());
        if (fFalcon)
        {
            if (size_t(pend - pbegin) != keydata.size())
            {
                fValid = false;
                return;
            }
            if (true) //(Check(&pbegin[0]))
            {
                memcpy(keydata.data(), (unsigned char *)&pbegin[0], keydata.size());
                fValid = true;
                fCompressed = fCompressedIn;
            }
            else
            {
                fValid = false;
            }
        }
        else
        {
            if (pend - pbegin != 32)
            {
                fValid = false;
                return;
            }
            if (Check(&pbegin[0]))
            {
                memcpy(vch, (unsigned char *)&pbegin[0], 32);
                fValid = true;
                fCompressed = fCompressedIn;
            }
            else
            {
                fValid = false;
            }
        }
    }

    //! Initialize using begin and end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend, CPubKey pk, bool fCompressedIn)
    {
        fFalcon = ((size_t)(pend - pbegin) >= keydata.size() && pk.IsFalcon());
        if (fFalcon)
        {
            if (size_t(pend - pbegin) != keydata.size())
            {
                fValid = false;
                return;
            }
            if (true) //(Check(&pbegin[0]))
            {
                memcpy(keydata.data(), (unsigned char *)&pbegin[0], keydata.size());
                memcpy(pubkeydata.data(), (unsigned char *)(pk.data()), pubkeydata.size());
                fValid = true;
                fCompressed = fCompressedIn;
            }
            else
            {
                fValid = false;
            }
        }
        else
        {
            fValid = false;
            if (pend - pbegin != 32)
            {
                fValid = false;
                return;
            }
            if (Check(&pbegin[0]))
            {
                memcpy(vch, (unsigned char *)&pbegin[0], 32);
                fValid = true;
                fCompressed = fCompressedIn;
            }
            else
            {
                fValid = false;
            }
        }
    }
    //! Simple read-only vector-like interface.
    unsigned int size() const
    {
        if (fFalcon)
            return (fValid ? keydata.size() : 0);
        else
            return (fValid ? 32 : 0);
    }
    const unsigned char *begin() const
    {
        if (fFalcon)
            return keydata.data();
        else
            return vch;
    }
    const unsigned char *end() const
    {
        if (fFalcon)
            return keydata.data() + size();
        else
            return vch + size();
    }
    unsigned int pksize() const
    {
        assert(fFalcon);
        return (fValid ? pubkeydata.size() : 0);
    }
    const unsigned char *pkbegin() const
    {
        assert(fFalcon);
        return pubkeydata.data();
    }
    const unsigned char *pkend() const
    {
        assert(fFalcon);
        return pubkeydata.data() + pksize();
    }
    //! Check whether this is a falcon key.
    bool IsFalcon() const { return fFalcon; }
    //! Check whether this private key is valid.
    bool IsValid() const { return fValid; }
    //! Check whether the public key corresponding to this private key is (to be) compressed.
    bool IsCompressed() const { return fCompressed; }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey(bool fCompressed, bool _fFalcon = false);

    /**
     * Convert the private key to a CPrivKey (serialized OpenSSL private key data).
     * This is expensive.
     */
    CPrivKey GetPrivKey() const;

    /**
     * Compute the public key from a private key.
     * This is expensive.
     */
    CPubKey GetPubKey() const;

    /**
     * Create a DER-serialized ECDSA signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool SignECDSA(const uint256 &hash, std::vector<unsigned char> &vchSig, uint32_t test_case = 0) const;

    /**
     * Create a Schnorr signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool SignSchnorr(const uint256 &hash, std::vector<uint8_t> &vchSig, uint32_t test_case = 0) const;

    /**
     * Create a Falcon signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool SignFalcon(const uint256 &hash, std::vector<uint8_t> &vchSig, uint32_t test_case = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const uint256 &hash, std::vector<unsigned char> &vchSig) const;

    //! Derive BIP32 child key.
    bool Derive(CKey &keyChild,
        ChainCode &ccChild,
        unsigned int nChild,
        const ChainCode &cc,
        bool _fFalcon = false) const;

    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     * (A signature is created then verified.)
     */
    bool VerifyPubKey(const CPubKey &vchPubKey) const;

    //! Load private key and check that public key matches.
    bool Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck);

    //! Check whether an element of a signature (r or s) is valid.
    static bool CheckSignatureElement(const unsigned char *vch, int len, bool half);
};

struct CExtKey
{
    unsigned char nDepth;
    unsigned char vchFingerprint[4];
    unsigned int nChild;
    ChainCode chaincode;
    CKey key;

    friend bool operator==(const CExtKey &a, const CExtKey &b)
    {
        return a.nDepth == b.nDepth && memcmp(&a.vchFingerprint[0], &b.vchFingerprint[0], 4) == 0 &&
               a.nChild == b.nChild && a.chaincode == b.chaincode && a.key == b.key;
    }

    void Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const;
    void Decode(const unsigned char code[BIP32_EXTKEY_SIZE]);
    bool Derive(CExtKey &out, unsigned int nChild, bool _fFalcon = false) const;
    CExtPubKey Neuter() const;
    void SetMaster(const unsigned char *seed, unsigned int nSeedLen);
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
        if (len != BIP32_EXTKEY_SIZE)
        {
            throw std::runtime_error("Invalid extended key size\n");
        }
        unsigned char code[BIP32_EXTKEY_SIZE];
        s.read((char *)&code[0], len);
        Decode(code);
    }
};

/** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
void ECC_Start(void);

/** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
void ECC_Stop(void);

/** Check that required EC support is available at runtime. */
bool ECC_InitSanityCheck(void);

/** Check that required falcon support is available at runtime. */
bool Falcon_InitSanityCheck(void);

/** Derive a BIP-0032 heirarchial deterministic wallet key */
int Hd32DeriveChildKey(CKey key, int externalChainCounter, CKey &secret, std::string *keypath);

/** Derive a BIP-0044 heirarchial deterministic wallet key */
int Hd44DeriveChildKey(const unsigned char *secretSeed,
    unsigned int secretSeedLen,
    unsigned int purpose,
    unsigned int coinType,
    unsigned int account,
    bool change,
    unsigned int index,
    CKey &secret,
    std::string *keypath);


#endif // NEXA_KEY_H
