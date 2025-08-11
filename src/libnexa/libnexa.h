// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNEXA_H
#define LIBNEXA_H

// Preface any Shared Library API definition with this macro.  This will ensure that the function is available for
// external linkage.
// For example:
// SLAPI int myExportedFunc(unsigned char *buf, int num);
// If windows build, export all the APIs as dll symbols
#ifndef CINTEROP
#ifdef __MINGW32__
#define SLAPI extern "C" __declspec(dllexport)
#else
#ifdef __MINGW64__
#define SLAPI extern "C" __declspec(dllexport)
#else
#define SLAPI extern "C" __attribute__((visibility("default")))
#endif
#endif
#endif

// This removes an unneeded define that confuses the Kotlin/Native binding program
#ifdef CINTEROP
#define SLAPI
#endif

#include "stdint.h"

#include <stdbool.h>

// clang-format off

// Major version MUST be incremented if any backward incompatible changes are
// introduced to the public API. It MAY also include minor and revision level changes.
// Minor and revision versions MUST be reset to 0 when major version is incremented.
#define LIBNEXA_MAJOR(major) 1000000 * major

// Minor version MUST be incremented if new, backward compatible functionality is
// introduced to the public API. It MUST be incremented if any public API
// functionality is marked as deprecated. It MAY be incremented if substantial
// new functionality or improvements are introduced within the private code.
// It MAY include patch level changes. Revision version MUST be reset to 0 when
// minor version is incremented.
#define LIBNEXA_MINOR(minor) 1000 * minor

// Revision version MUST be incremented if only backward compatible bug fixes are
// introduced. A bug fix is defined as an internal change that fixes incorrect behavior.
#define LIBNEXA_REVISION(revision) 1 * revision
static const int32_t LIBNEXA_VERSION = LIBNEXA_MAJOR(1) + LIBNEXA_MINOR(2) + LIBNEXA_REVISION(1);

// clang-format on

// libnexa version
SLAPI int32_t libnexaVersion();
SLAPI uint32_t libnexa_version();

// returns the error code of the last error
SLAPI uint32_t get_libnexa_error();
// puts the last error in the buffer. if the buffer is not large enough to hold the error,
// the buffer will be filled but may not contain the entire error message
SLAPI char *get_libnexa_error_string(uint32_t *resultLen);

// frees a pointer returned by libnexa
SLAPI void libnexa_free(void *ptr);

// Begin v1 API

/** Returns 0 if invalid, -sizeNeeded if you did not give a large enough buffer, or the length of the result if it
    worked.
 */
SLAPI int encode64(const unsigned char *data, int size, char *result, int resultMaxLen);
SLAPI int decode64(const char *data, unsigned char *result, int resultMaxLen);

/** Convert binary data to a hex string.  The provided result buffer must be 2*length+1 bytes.
 */
SLAPI int Bin2Hex(const unsigned char *val, int length, char *result, unsigned int resultLen);

/** Derive a BIP-0044 heirarchial deterministic wallet key */
SLAPI int hd44DeriveChildKey(const unsigned char *secretSeed,
    unsigned int secretSeedLen,
    unsigned int purpose,
    unsigned int coinType,
    unsigned int account,
    bool change,
    unsigned int index,
    unsigned char *secret,
    char *keypath);

/** Given a private key, return its corresponding public key */
SLAPI int GetPubKey(const unsigned char *keyData, unsigned char *result, unsigned int resultLen);

/** Sign data (compatible with BCH OP_CHECKDATASIG) */
SLAPI int SignHashEDCSA(const unsigned char *data,
    int datalen,
    const unsigned char *secret,
    unsigned char *result,
    unsigned int resultLen);

/** Calculates the id of the passed serialized transaction.  Result must be 32 bytes */
SLAPI int txid(const unsigned char *txData, int txbuflen, unsigned char *result);

/** Calculates the idem of the passed serialized transaction.  Result must be 32 bytes */
SLAPI int txidem(const unsigned char *txData, int txbuflen, unsigned char *result);

/** Calculates the hash of the passed in serialised block header. Result must be 32 bytes */
SLAPI int blockHash(const unsigned char *data, int len, unsigned char *result);

/** Sign one input of a transaction using an ECDSA signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
*/
SLAPI int SignTxECDSA(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    uint32_t nHashType,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

/** Sign one input of a transaction using a Schnorr signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI int signBchTxOneInputUsingSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    uint32_t nHashType,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

/** Sign one input of a transaction using a Schnorr signature
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI int signTxOneInputUsingSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

/* DEPRECATED: same as SignTxOneInputUsingSchnorr */
SLAPI int SignTxSchnorr(const unsigned char *txData,
    int txbuflen,
    unsigned int inputIdx,
    int64_t inputAmount,
    const unsigned char *prevoutScript,
    uint32_t priorScriptLen,
    const unsigned char *hashType,
    unsigned int hashTypeLen,
    const unsigned char *keyData,
    unsigned char *result,
    unsigned int resultLen);

/** TODO convenience function that hashes the provided data.
 *    Sign data via the Schnorr signature algorithm.
 *    All buffer arguments should be in binary-serialized data.
 *    The returned signature will not have a sighashtype byte.
 *
 * SLAPI int SignDataSchnorr(const unsigned char *data, int datalen,
 *    const unsigned char *keyData,
 *    unsigned char *result);
 */

/* Sign a hash (presumably the hash of some data) using a Schnorr signature.  Result must be at least 64 bytes. */
SLAPI int signHashSchnorr(const unsigned char *hash, const unsigned char *keyData, unsigned char *result);

/* Sign a hash (presumably the hash of some data) using a Schnorr signature, with the provided 32 byte private nonce
   (often specified as 'k' in the Schnorr sig description.  Result must be at least 64 bytes. */
SLAPI int signHashSchnorrWithNonce(const unsigned char *hash,
    const unsigned char *keyData,
    const unsigned char *nonce,
    unsigned char *result);

// takes in the op_return script bytes of the token genesis
// returns an ascii encoded json object that is the token genesis description in out
// outlen is the size of the out buffer being written to. a description larger than
// outlen returns an error
// returns the length of the data in out
SLAPI int parseGroupDescription(const uint8_t *in, const uint64_t inlen, uint8_t *out, uint64_t outlen);

// takes in a scriptPubKey of a P2ST addr and returns the argshah of the addr, in most casts this will be the pubkeyhash
// fails immediately if the out size is less than 20 bytes as the hash being returned is 20 bytes
// returns 0 on failure and puts error code in error param
// returns the length of the data in out on success
SLAPI int getArgsHashFromScriptPubkey(const uint8_t *spkIn, const uint64_t spkInLen, uint8_t *out, uint64_t outlen);

// same as getArgsHashFromScriptPubkey above except it returns the template hash
SLAPI int getTemplateHashFromScriptPubkey(const uint8_t *spkIn, const uint64_t spkInLen, uint8_t *out, uint64_t outlen);


SLAPI int getGroupTokenInfoFromScriptPubkey(const uint8_t *scriptIn,
    const uint64_t scriptInLen,
    uint8_t *grpId,
    const uint64_t grpIdlimit,
    uint64_t *grpFlags,
    int64_t *grpAmount);

// Returns <= 0 if error, size of result if good.
SLAPI int signMessage(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *secret,
    unsigned int secretLen,
    unsigned char *result,
    unsigned int resultLen);

// returns 0 if error, -size if recovered pubkey does not match addr (with pubkey in result), +size if match
SLAPI int verifyMessage(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *addr,
    unsigned int addrLen,
    const unsigned char *sig,
    unsigned int sigLen,
    unsigned char *result,
    unsigned int resultLen);

SLAPI bool verifyBlockHeader(int chainSelector, const unsigned char *serializedHeader, int serLen);

SLAPI int encodeCashAddr(int chainSelector,
    int typ,
    const unsigned char *data,
    int len,
    char *result,
    int resultMaxLen);

SLAPI int decodeCashAddr(int chainSelector, const char *addrstr, unsigned char *result, int resultMaxLen);

SLAPI int decodeCashAddrContent(int chainSelector,
    const char *addrstr,
    unsigned char *result,
    int resultMaxLen,
    unsigned char *type);

SLAPI int serializeScript(const uint8_t *script, const unsigned int lenScript, uint8_t *result, int resultMaxLen);

SLAPI int pubkeyToScriptTemplate(const unsigned char *pubkey, int lenPubkey, unsigned char *result, int resultMaxLen);

SLAPI int groupIdFromAddr(int chainSelector, const char *addrstr, unsigned char *result, int resultMaxLen);

SLAPI int groupIdToAddr(int chainSelector, const unsigned char *data, int len, char *result, int resultMaxLen);

SLAPI int decodeWifPrivateKey(int chainSelector, const char *secretWIF, unsigned char *result, int resultMaxLen);

/** Get work from nbits */
SLAPI void getWorkFromDifficultyBits(unsigned long int nBits, unsigned char *result);

SLAPI unsigned int getDifficultyBitsFromWork(unsigned char *work256Bits);

/** Create a bloom filter
The size of the result array must be allocated to be at least 32 bytes bigger than maxSize to account for the
serialization overhead.
*/
SLAPI int createBloomFilter(const unsigned char *data,
    unsigned int len,
    double falsePosRate,
    int capacity,
    int maxSize,
    int flags,
    int tweak,
    unsigned char *result);

SLAPI int extractFromMerkleBlock(int numTxes,
    const unsigned char *merkleProofPath,
    int mppLen,
    const unsigned char *hashIn,
    int numHashes,
    unsigned char *result,
    int resultLen);

SLAPI int capdSolve(const unsigned char *message, unsigned int msgLen, unsigned char *result, unsigned int resultLen);
SLAPI int capdCheck(const unsigned char *message, unsigned int msgLen);
SLAPI int capdHash(const unsigned char *message, unsigned int msgLen, unsigned char *result, unsigned int resultLen);

SLAPI int capdSetPowTargetHarderThanPriority(const unsigned char *message,
    const unsigned int msgLen,
    const double priority,
    unsigned char *result,
    const unsigned int resultLen);

// encrypt must be 1 (encrypt) or 0 (decrypt).
// len must be a multiple of 16
// secret must be 32 bytes, iv must be 16 or more bytes
// result buffer length must be len (or more) bytes
SLAPI int cryptAES256CBC(unsigned int encrypt,
    const unsigned char *data,
    unsigned int len,
    const unsigned char *secret,
    const unsigned char *iv,
    unsigned char *result);

SLAPI bool verifyDataSchnorr(const unsigned char *message,
    unsigned int msgLen,
    const unsigned char *pubkey,
    int lenPubkey,
    const unsigned char *sig);

SLAPI bool verifyHashSchnorr(const unsigned char *hash,
    const unsigned char *pubkey,
    int lenPubkey,
    const unsigned char *sig);

/** Return random bytes from cryptographically acceptable random sources */
SLAPI int RandomBytes(unsigned char *buf, int num);

// End v1 API
//
//
//
//
//
// Begin v2 API

/** Convert binary data to a hex string.  The provided result buffer must be 2*length+1 bytes.
 */
SLAPI char *bin_to_hex(const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen);

SLAPI bool capd_check(const uint8_t *message, const uint32_t messageLen);

SLAPI uint8_t *capd_hash(const uint8_t *message, const uint32_t messageLen, uint32_t *resultLen);

SLAPI uint8_t *capd_set_pow_target_harder_than_priority(const uint8_t *message,
    const uint32_t messageLen,
    const double priority,
    uint32_t *resultLen);

SLAPI uint8_t *capd_solve(const uint8_t *message, const uint32_t messageLen, uint32_t *resultLen);

/** Create a bloom filter */
SLAPI uint8_t *create_bloom_filter(const uint8_t *data,
    const uint32_t len,
    const double falsePositiveRate,
    const uint32_t capacity,
    const uint32_t maxSize,
    const int32_t flags,
    const int32_t tweak,
    uint32_t *resultLen);

// result buffer length must be len (or more) bytes, secret must be 32 bytes, iv must be 16 or more bytes, len must be a
// multiple of 16
SLAPI uint8_t *crypt_aes_256_cbc(const bool encrypt,
    const uint8_t *data,
    const uint32_t len,
    const uint8_t *secret,
    const uint8_t *iv,
    uint32_t *resultLen);

SLAPI char *decode_base64(const char *data, uint32_t *resultLen);

SLAPI uint8_t *decode_cash_addr(const int32_t chain, const char *strAddr, uint32_t *resultLen);

SLAPI uint8_t *decode_cash_addr_content(const int32_t chain, const char *strAddr, uint32_t *resultLen, uint8_t *type);

SLAPI uint8_t *decode_wif_private_key(const int32_t chain, const char *privateKeyWIF, uint32_t *resultLen);

SLAPI char *encode_base64(const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen);

SLAPI char *encode_cash_addr(const int32_t chain,
    const int32_t typ,
    const uint8_t *data,
    const uint32_t dataLen,
    uint32_t *resultLen);

// Since partial Merkle blocks are just trees of hashes, this structure is the same for Nexa and BCH
SLAPI uint8_t *extract_from_merkle_block(const int32_t numTxes,
    const uint8_t *merkleProofPath,
    const int32_t mppLen,
    const uint8_t *hashIn,
    const uint32_t numHashes,
    uint32_t *resultLen);

SLAPI uint8_t *get_args_hash_from_script_pubkey(const uint8_t *scriptData,
    const uint32_t scriptDataLen,
    uint32_t *resultLen);

SLAPI uint32_t get_difficulty_bits_from_work(const uint8_t *work256Bits);

SLAPI uint8_t *get_group_info_from_script_pubkey(const uint8_t *scriptData,
    const uint32_t scriptDataLen,
    uint32_t *resultLen,
    uint64_t *grpFlags,
    int64_t *grpAmount);

/** Given a private key, return its corresponding public key */
SLAPI uint8_t *get_pubkey(const uint8_t *keyData, uint32_t *resultLen);

SLAPI uint8_t *get_template_hash_from_script_pubkey(const uint8_t *scriptData,
    const uint32_t scriptDataLen,
    uint32_t *resultLen);

SLAPI uint8_t *get_txid(const uint8_t *txData, const uint32_t txDataLen, uint32_t *resultLen);

SLAPI uint8_t *get_txidem(const uint8_t *txData, const uint32_t txDataLen, uint32_t *resultLen);

/** Get work from nbits */
SLAPI uint8_t *get_work_from_difficulty_bits(const uint32_t numBits, uint32_t *resultLen);

SLAPI uint8_t *group_id_from_addr(const int32_t chain, const char *addr, uint32_t *resultLen);

SLAPI char *group_id_to_addr(const int32_t chain, const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen);

// result must be 20 bytes
SLAPI uint8_t *hash160(const uint8_t *data, const uint32_t dataLen);

// result must be 32 bytes
SLAPI uint8_t *hash256(const uint8_t *data, const uint32_t dataLen);

SLAPI uint8_t *hash_block_header(const uint8_t *blockData, const uint32_t blockDataLen, uint32_t *resultLen);

/** Derive a BIP-0044 heirarchial deterministic wallet key */
SLAPI uint8_t *hd44_derive_child_key(const uint8_t *secretSeed,
    const uint32_t secretSeedLen,
    const uint32_t purpose,
    const uint32_t coinType,
    const uint32_t account,
    const bool change,
    const uint32_t index,
    uint32_t *resultLen);

SLAPI uint8_t *parse_group_description(const uint8_t *input, const uint32_t inputLen, uint32_t *resultLen);

SLAPI uint8_t *pubkey_to_script_template(const uint8_t *pubkey, const uint32_t pubkeyLen, uint32_t *resultLen);

/** Return random bytes from cryptographically acceptable random sources */
SLAPI uint8_t *random_bytes(const uint32_t num);

SLAPI uint8_t *recover_pubkey_from_signature(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *sig,
    const uint32_t sigLen,
    uint32_t *resultLen);

SLAPI uint8_t *serialise_script(const uint8_t *script, const uint32_t scriptLen, uint32_t *resultLen);

// result must be 32 bytes
SLAPI uint8_t *sha256(const uint8_t *data, const uint32_t dataLen);

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI uint8_t *sign_bch_tx_one_input_using_schnorr(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t hashType,
    const uint8_t *privkey,
    uint32_t *resultLen);

/** Sign data (compatible with BCH OP_CHECKDATASIG) */
SLAPI uint8_t *sign_hash_ecdsa(const uint8_t *data, const uint32_t dataLen, const uint8_t *secret, uint32_t *resultLen);

/** Sign data via the Schnorr signature algorithm.  hash must be 32 bytes.
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.

    The returned signature will not have a sighashtype byte.
*/
SLAPI uint8_t *sign_hash_schnorr(const uint8_t *hash, const uint8_t *privkey, uint32_t *resultLen);

SLAPI uint8_t *sign_hash_schnorr_with_nonce(const uint8_t *hash,
    const uint8_t *privkey,
    const uint8_t *nonce,
    uint32_t *resultLen);

SLAPI uint8_t *sign_message(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *secret,
    const uint32_t secretLen,
    uint32_t *resultLen);

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Returns length of returned signature.
*/
SLAPI uint8_t *sign_tx_ecdsa(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t hashType,
    const uint8_t *privkey,
    uint32_t *resultLen);

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
*/
SLAPI uint8_t *sign_tx_one_input_using_schnorr(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t *hashType,
    const uint32_t hashTypeLen,
    const uint8_t *privkey,
    uint32_t *resultLen);

SLAPI bool verify_block_header(const int32_t chain,
    const uint8_t *serialisedHeader,
    const uint32_t serialisedHeaderLen);

// sig must be 64 bytes
SLAPI bool verify_data_schnorr(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *pubkey,
    const uint32_t pubkeyLen,
    const uint8_t *sig);

// sig must be 64 bytes
SLAPI bool verify_hash_schnorr(const uint8_t *hash,
    const uint8_t *pubkey,
    const uint32_t pubkeyLen,
    const uint8_t *sig);

SLAPI bool verify_message(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *addr, // TODO - This is not actually addr but hash160 of pubkey?
    const uint32_t addrLen,
    const uint8_t *sig,
    const uint32_t sigLen);

// End v2 API

#endif /* CASHLIB_H */
