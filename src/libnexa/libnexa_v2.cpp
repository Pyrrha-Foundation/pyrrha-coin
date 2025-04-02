// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa.h"
#include "libnexa_common.h"

#ifdef DEBUG
#ifdef IOS
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#else // not IOS
#define p(...) // tinyformat::format(std::cout, __VA_ARGS__)
#endif // IOS
#else // not DEBUG
#define p(...)
#endif // DEBUG

#define CHECK_SIZE(nBytes)                                  \
    if (nBytes > std::numeric_limits<int>::max())           \
    {                                                       \
        set_error(LIBNEXA_ERROR::RETURN_FAILURE,            \
        "number of bytes to be returned is too large \n");  \
        *resultLen = 0;                                     \
        return nullptr;                                     \
    }                                                       \



// in headervalidation.cpp
bool CheckBlockHeader(const Consensus::Params &consensusParams,
    const CBlockHeader &block,
    CValidationState &state,
    bool fCheckPOW);

SLAPI uint32_t libnexa_version() { return LIBNEXA_VERSION; }

SLAPI uint32_t get_libnexa_error() { return get_error_code(); }

SLAPI char* get_libnexa_error_string(uint32_t *resultLen)
{
    const std::string strError = get_error_string();
    const size_t errorLen = strError.size() + 1; // +1 for null term
    char *result = (char *)std::calloc(errorLen, 1);
    std::memcpy(result, strError.c_str(), errorLen);
}

SLAPI void libnexa_free(void* ptr)
{
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    free(ptr);
}



/** Convert binary data to a hex string.  The provided result buffer must be 2*length+1 bytes.
 */
SLAPI char* bin_to_hex(const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen)
{
    const std::string hexStr = GetHex(data, dataLen);
    const size_t hexStrLen = hexStr.size() + 1; // add one for null term
    CHECK_SIZE(hexStrLen);
    char *result = (char *)std::calloc(hexStrLen, 1);
    std::strncpy(result, hexStr.c_str(), hexStrLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)hexStrLen;
    return result;
}

SLAPI bool capd_check(const uint8_t *message, const uint32_t messageLen)
{
    CDataStream stream(message, message + messageLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        stream >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        return false;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return msg.DoesPowMeetTarget();
}

SLAPI uint8_t* capd_hash(const uint8_t *message, const uint32_t messageLen, uint32_t *resultLen)
{
    CDataStream stream(message, message + messageLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        stream >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        *resultLen = 0;
        return nullptr;
    }
    const uint256 hash = msg.CalcHash();
    const size_t sz = hash.size();
    CHECK_SIZE(sz);
    uint8_t* result = (uint8_t*)std::malloc(sz);
    std::memcpy(result, hash.begin(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = sz;
    return result;
}

SLAPI uint8_t* capd_set_pow_target_harder_than_priority(const uint8_t *message,
    const uint32_t messageLen,
    const double priority,
    uint32_t *resultLen)
{
    CDataStream stream(message, message + messageLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        stream >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        *resultLen = -1;
        return nullptr;
    }
    msg.SetPowTargetHarderThanPriority(priority);
    CDataStream returnStream(SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        returnStream << msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd serialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to encode to a capd message\n");
        *resultLen  = -2;
        return nullptr;
    }
    const size_t returnStreamSize = returnStream.size();
    CHECK_SIZE(returnStreamSize);
    uint8_t* result = (uint8_t*)std::malloc(returnStreamSize);
    std::memcpy(result, returnStream.data(), returnStreamSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = returnStream.size();
    return result;
}

SLAPI uint8_t* capd_solve(const uint8_t *message, const uint32_t messageLen, uint32_t *resultLen)
{
    CDataStream stream(message, message + messageLen, SER_NETWORK, PROTOCOL_VERSION);
    CapdMsg msg;
    try
    {
        stream >> msg;
    }
    catch (const std::exception &)
    {
        p("libnexa capd deserialize error");
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in failed to decode to a capd message\n");
        *resultLen = 1;
        return nullptr;
    }
    // one year of seconds.  This is not going to work because Solve interprets this as an offset from "now" and changes
    // the message time field.  But we do not return the changed time.  Callers should manually do this if they
    // want an offset.  Since such an ancient message is unrelayable this must be an invalid capd message anyway.
    if (msg.createTime < 31536000)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "message create time must be at least 31536000\n");
        *resultLen = -2;
        return nullptr;
    }
    const bool solved = msg.Solve(msg.createTime);
    if (solved)
    {
        const size_t msgNonceLen = msg.nonce.size();
        uint8_t* result = (uint8_t*)std::malloc(msgNonceLen);
        std::memcpy(result, msg.nonce.data(), msgNonceLen);
        set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
        *resultLen = msgNonceLen;
        return result;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = 0;
    return nullptr;
}

/** Create a bloom filter */
SLAPI uint8_t* create_bloom_filter(const uint8_t *data,
    const uint32_t len,
    const double falsePositiveRate,
    const uint32_t capacity,
    const uint32_t maxSize,
    const int32_t flags,
    const int32_t tweak,
    uint32_t *resultLen)
{
    if (capacity < 10)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "capacity can not be less than 10\n");
        *resultLen = 0;
        return nullptr;
    }
    if (falsePositiveRate < 0)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "false positive rate less than 0.0\n");
        *resultLen = 0;
        return nullptr;
    }
    if (falsePositiveRate > 1.0)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "false positive rate greater than 1.0\n");
        *resultLen = 0;
        return nullptr;
    }

    const uint32_t maxx = (capacity > len) ? capacity : len;
    CBloomFilter bloom(maxx, falsePositiveRate, tweak, flags, maxSize);

    const uint8_t *elemData = data;
    while (elemData - data < len)
    {
        int elemLen = *elemData; // first byte is the length of the element
        elemData++;
        bloom.insert(std::vector<uint8_t>(elemData, elemData + elemLen));
        elemData += elemLen;
    }

    CDataStream serializer(SER_NETWORK, PROTOCOL_VERSION);
    serializer << bloom;
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "Bloom size: %d Bloom serialized size: %d numAddrs: %d\n",
    //    (unsigned int)bloom.vDataSize(), (unsigned int)serializer.size(), (unsigned int)len);
    const size_t sz = serializer.size();
    CHECK_SIZE(sz);
    uint8_t* result = (uint8_t*)std::malloc(sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    memcpy(result, serializer.data(), sz);
    *resultLen = (uint32_t)sz;
    return result;
}

// result buffer length must be len (or more) bytes, secret must be 32 bytes, iv must be 16 or more bytes, len must be a
// multiple of 16
SLAPI uint8_t* crypt_aes_256_cbc(const bool encrypt,
    const uint8_t *data,
    const uint32_t len,
    const uint8_t *secret,
    const uint8_t *iv,
    uint32_t *resultLen)
{
    int nBytes = 0;
    // sanity check len
    CHECK_SIZE(len);
    uint8_t* result = (uint8_t*)std::malloc(len); // aes output always same length as input
    if (encrypt)
    {
        AES256CBCEncrypt crypter(secret, iv, false);
        nBytes = crypter.Encrypt(data, len, result);
    }
    else // if (encrypt == 0)
    {
        AES256CBCDecrypt crypter(secret, iv, false);
        nBytes = crypter.Decrypt(data, len, result);
    }
    if (nBytes == 0)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "internal AES error, no bytes processed\n");
        *resultLen = 0;
        return nullptr;
    }
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = len;
    return result;
}

SLAPI char* decode_base64(const char* data, uint32_t *resultLen)
{
    bool invalid = true;
    const std::vector<uint8_t> decodedData = DecodeBase64(data, &invalid);
    const size_t decodedSize = decodedData.size() + 1; // +1 for null term
    if (invalid)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in was invalid base64\n");
        *resultLen = 0;
        return nullptr;
    }
    CHECK_SIZE(decodedSize);
    char *result = (char *)std::calloc(decodedSize, 1);
    std::memcpy(result, decodedData.data(), decodedSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)decodedSize;
    return result;
}

SLAPI uint8_t* decode_cash_addr(const int32_t chain, const char *strAddr, uint32_t *resultLen)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chain);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    const CTxDestination dst = DecodeCashAddr(strAddr, *cp);
    std::vector<uint8_t> resultv;
    std::visit(PubkeyExtractor(resultv, *cp), dst);
    const int sz = resultv.size();
    CHECK_SIZE(sz);
    uint8_t* result = (uint8_t*)std::malloc(sz);
    memcpy(result, &resultv[0], sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sz;
    return result;
}

SLAPI uint8_t* decode_cash_addr_content(const int32_t chain,
    const char *strAddr,
    uint32_t *resultLen,
    uint8_t *type)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chain);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    const CashAddrContent content = DecodeCashAddrContent(strAddr, *cp);
    const size_t hashSize = content.hash.size();
    uint8_t* result = (uint8_t*)std::malloc(hashSize);
    CHECK_SIZE(hashSize);
    memcpy(result, &content.hash[0], hashSize);
    memcpy(type, &content.type, 1);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)hashSize;
    return result;
}

SLAPI uint8_t* decode_wif_private_key(const int32_t chain, const char *privateKeyWIF, uint32_t *resultLen)
{
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chain));
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    CBitcoinSecret secret;
    const bool ok = secret.SetString(*cp, privateKeyWIF);
    if (!ok)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid wif private key\n");
        *resultLen = 0;
        return nullptr;
    }
    const CKey key = secret.GetKey();
    if (!key.IsValid())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid key generated from wif private key\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t sz = key.size();
    CHECK_SIZE(sz);
    uint8_t* result = (uint8_t*)std::malloc(sz);
    std::memcpy(result, key.begin(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sz;
    return result;
}

SLAPI char* encode_base64(const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen)
{
    const std::string encodedData = EncodeBase64(data, dataLen);
    const size_t outSize = encodedData.size() + 1; // +1 for null term
    CHECK_SIZE(outSize);
    char *result = (char *)std::calloc(outSize, 1);
    std::strncpy(result, encodedData.c_str(), outSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)outSize;
    return result;
}

SLAPI char* encode_cash_addr(const int32_t chain, const int32_t typ, const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen)
{
    CTxDestination dst = CNoDestination();

    if ((typ == PayAddressTypeP2PKH) || (typ == PayAddressTypeP2SH))
    {
        if (dataLen != 20)
        {
            set_error(LIBNEXA_ERROR::INVALID_ARG, "type was p2pkh or p2sh but the address len was not 20 bytes\n");
            *resultLen = 0;
            return nullptr;
        }
        const uint160 tmp((const uint8_t *)data);
        if (typ == PayAddressTypeP2PKH)
        {
            dst = CKeyID(tmp);
        }
        else if (typ == PayAddressTypeP2SH)
        {
            dst = CScriptID(tmp);
        }
    }
    else if (typ == PayAddressTypeTEMPLATE)
    {
        // A PayAddress contains a serialized script
        // Really the "right" way to do this is to just encode the exact bytes without stripping off
        // the serialization and putting it back on but that does not work with the "Destination" code.
        // As it is, any additional parts (currently none are defined) to the PayAddress will be removed
        ScriptTemplateDestination st;
        const std::vector<uint8_t> vec(data, data + dataLen);
        CDataStream ssData(vec, SER_NETWORK, PROTOCOL_VERSION);
        ssData >> st;
        dst = st;
    }
    else
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid addres type provided\n");
        *resultLen = 0;
        return nullptr;
    }

    const CChainParams *cp = GetChainParams((ChainSelector)chain);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    const std::string addrAsStr(EncodeCashAddr(dst, *cp));
    const size_t sz = addrAsStr.size() + 1; // add one for null terminating char
    CHECK_SIZE(sz);
    char *result = (char *)std::calloc(sz, 1);
    std::strncpy(result, addrAsStr.c_str(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sz;
    return result;
}

// Since partial Merkle blocks are just trees of hashes, this structure is the same for Nexa and BCH
SLAPI uint8_t* extract_from_merkle_block(const int32_t numTxes,
    const uint8_t *merkleProofPath,
    const int32_t mppLen,
    const uint8_t *hashIn,
    const uint32_t numHashes,
    uint32_t *resultLen)
{
    const unsigned int HASH_LEN = 32;
    CDecodablePartialMerkleTree tree(numTxes, merkleProofPath, mppLen);
    // Copy the hashes out of the array into the PartialMerkleTree
    std::vector<uint256> &hashes = tree.accessHashes();
    hashes.resize(numHashes);
    for (size_t i = 0; i < (unsigned int)numHashes; i++)
    {
        hashes[i] = uint256(hashIn + (i * HASH_LEN));
    }

    std::vector<uint256> matches;
    std::vector<uint32_t> matchIndexes;
    const uint256 merkleRoot = tree.ExtractMatches(matches, matchIndexes);

    const size_t fullSize = (matches.size() + 1) * HASH_LEN;
    CHECK_SIZE(fullSize);
    const uint32_t sz = (uint32_t) fullSize;
    uint8_t* result = (uint8_t*)std::malloc(sz);
    uint8_t *dest = result;
    const uint8_t *end = result + (sz * HASH_LEN);


    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    if (dest + HASH_LEN > end)
    {
        *resultLen = sz;
        return result;
    }

    std::memcpy(dest, merkleRoot.begin(), HASH_LEN);

    dest += HASH_LEN;
    if (dest > end)
    {
        *resultLen = sz;
        return result;
    }

    // Fill the rest with transaction hashes
    for (size_t i = 0; i < matches.size(); i++)
    {
        std::memcpy(dest, matches[i].begin(), HASH_LEN);
        dest += HASH_LEN;
        if (dest > end)
        {
            *resultLen = sz;
            return result;
        }
    }
    *resultLen = sz;
    return result;
}

SLAPI uint8_t* get_args_hash_from_script_pubkey(const uint8_t *scriptData, const uint32_t scriptDataLen, uint32_t *resultLen)
{
    CScript script(scriptData, scriptData + scriptDataLen);
    script.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    const ScriptTemplateError sctError = GetScriptTemplate(script, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t argsHashLen = argsHash.size();
    CHECK_SIZE(argsHashLen);
    uint8_t* result = (uint8_t*)std::malloc(argsHashLen);
    std::copy(argsHash.begin(), argsHash.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = argsHashLen;
    return result;
}

SLAPI uint32_t get_difficulty_bits_from_work(const uint8_t *work256Bits)
{
    const uint256 ui(work256Bits);
    arith_uint256 work = UintToArith256(ui);
    // we need to compute ((2**256)/x) - 1
    // ~x (bitflip) is mathematically (2**256) - 1 - x
    // ~x/x is (2**256)/x - 1/x - x/x or (2**256)/x - 1 because 1/x is 0 in integral math
    work = ~work / work;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return work.GetCompact(false);
}

SLAPI uint8_t* get_group_info_from_script_pubkey(const uint8_t *scriptData,
    const uint32_t scriptDataLen,
    uint32_t *resultLen,
    uint64_t *grpFlags,
    int64_t *grpAmount)
{
    CScript script(scriptData, scriptData + scriptDataLen);
    script.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    ScriptTemplateError sctError = GetScriptTemplate(script, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        *resultLen = -1;
        return nullptr;
    }
    const size_t groupIdLen = groupInfo.associatedGroup.bytes().size();
    CHECK_SIZE(groupIdLen);
    uint8_t* result = (uint8_t*)std::malloc(groupIdLen);
    std::copy(groupInfo.associatedGroup.bytes().begin(), groupInfo.associatedGroup.bytes().end(), result);
    *grpFlags = (uint64_t)groupInfo.controllingGroupFlags;
    *grpAmount = groupInfo.quantity;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)groupIdLen;
    return result;
}

/** Given a private key, return its corresponding public key */
SLAPI uint8_t* get_pubkey(const uint8_t *keyData, uint32_t *resultLen)
{
    checkSigInit();
    const CKey key = LoadKey(keyData);
    if (key.IsValid() == false)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    const CPubKey pubkey = key.GetPubKey();
    const size_t pubkeySize = pubkey.size();
    CHECK_SIZE(pubkeySize);
    uint8_t* result = (uint8_t*)std::malloc(pubkeySize);
    std::copy(pubkey.begin(), pubkey.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)pubkeySize;
    return result;
}

SLAPI uint8_t* get_template_hash_from_script_pubkey(const uint8_t *scriptData, const uint32_t scriptDataLen, uint32_t *resultLen)
{
    CScript script(scriptData, scriptData + scriptDataLen);
    script.type = ScriptType::TEMPLATE;
    CGroupTokenInfo groupInfo;
    std::vector<uint8_t> templateHash;
    std::vector<uint8_t> argsHash;

    const ScriptTemplateError sctError = GetScriptTemplate(script, &groupInfo, &templateHash, &argsHash, nullptr);
    if (sctError != ScriptTemplateError::OK)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get script template from script provided\n");
        *resultLen = -1;
        return nullptr;
    }
    const size_t templateHashLen = templateHash.size();
    CHECK_SIZE(templateHashLen);
    uint8_t* result = (uint8_t*)std::malloc(templateHashLen);
    std::copy(templateHash.begin(), templateHash.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = templateHashLen;
    return result;
}

SLAPI uint8_t* get_txid(const uint8_t *txData, const uint32_t txDataLen, uint32_t *resultLen)
{
    CTransaction tx;
    CDataStream stream(txData, txData + txDataLen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        stream >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }
    const uint256 ret = tx.GetId();
    // no need to CHECK_SIZE for retlen, will always be 64
    uint8_t* result = (uint8_t*)std::malloc(ret.size());
    std::memcpy(result, ret.begin(), ret.size());
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)ret.size();
    return result;
}

SLAPI uint8_t* get_txidem(const uint8_t *txData, const uint32_t txDataLen, uint32_t *resultLen)
{
    CTransaction tx;
    CDataStream stream(txData, txData + txDataLen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        stream >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }
    const uint256 ret = tx.GetIdem();
    // no need to CHECK_SIZE retlen, will always be 64
    uint8_t* result = (uint8_t*)std::malloc(ret.size());
    std::memcpy(result, ret.begin(), ret.size());
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)ret.size();
    return result;
}

/** Get work from nbits */
SLAPI uint8_t* get_work_from_difficulty_bits(const uint32_t numBits, uint32_t *resultLen)
{
    const arith_uint256 work = GetWorkForDifficultyBits(numBits);
    uint256 ui = ArithToUint256(work);
    ui.reverse();
    // no need to CHECK_SIZE on 32
    uint8_t* result = (uint8_t*)std::malloc(32);
    std::memcpy(result, ui.begin(), 32);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return result;
}

SLAPI uint8_t* group_id_from_addr(const int32_t chain, const char *addr, uint32_t *resultLen)
{
    const CChainParams *cp = GetChainParams((ChainSelector)chain);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    CGroupTokenID gid = DecodeGroupToken(addr, *cp);
    const size_t size = gid.bytes().size();
    if (size < 32) // min group id size
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data < 32 bytes\n");
        *resultLen = 0;
        return nullptr;
    }
    if (size > 520) // max group id size
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data > 520 bytes\n");
        *resultLen = 0;
        return nullptr;
    }
    CHECK_SIZE(size);
    uint8_t* result = (uint8_t*)std::malloc(size);
    std::memcpy(result, &gid.bytes().front(), size);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)size;
    return result;
}

SLAPI char* group_id_to_addr(const int32_t chain, const uint8_t *data, const uint32_t dataLen, uint32_t *resultLen)
{
    if (dataLen < 32)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data < 32 bytes\n");
        *resultLen = 0;
        return nullptr;
    }
    if (dataLen > 520)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input data > 520 bytes\n");
        *resultLen = 0;
        return nullptr;
    }
    CGroupTokenID grp(data, dataLen);
    const CChainParams *cp = GetChainParams((ChainSelector)chain);
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        *resultLen = 0;
        return nullptr;
    }
    const std::string addrAsStr(EncodeGroupToken(grp, *cp));
    const size_t sz = addrAsStr.size() + 1; // add one for null terminating char
    CHECK_SIZE(sz);
    char *result = (char *)std::calloc(sz, 1);
    std::strncpy(result, addrAsStr.c_str(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sz;
    return result;
}

// result must be 20 bytes
SLAPI uint8_t* hash160(const uint8_t *data, uint32_t len)
{
    CHash160 hash;
    hash.Write(data, len);
    uint8_t* result = (uint8_t*)std::malloc(CHash160::OUTPUT_SIZE);
    hash.Finalize(result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return result;
}

// result must be 32 bytes
SLAPI uint8_t* hash256(const uint8_t *data, uint32_t len)
{
    CHash256 hash;
    hash.Write((const unsigned char *)data, len);
    uint8_t* result = (uint8_t*)std::malloc(CHash256::OUTPUT_SIZE);
    hash.Finalize(result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return result;
}

SLAPI uint8_t* hash_block_header(const uint8_t *blockData, const uint32_t blockDataLen, uint32_t *resultLen)
{
    CDataStream stream(blockData, blockData + blockDataLen, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader blockHeader;
    try
    {
        stream >> blockHeader;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "block header data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }
    const uint256 hash = blockHeader.GetHash();
    // no need to CHECK_SIZE hashlen, will always be 64
    const size_t hashLen = hash.size();
    uint8_t* result = (uint8_t*)std::malloc(hashLen);
    std::memcpy(result, hash.begin(), hashLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = hashLen;
    return result;
}

/** Derive a BIP-0044 heirarchial deterministic wallet key */
SLAPI uint8_t* hd44_derive_child_key(const uint8_t *secretSeed,
    const uint32_t secretSeedLen,
    const uint32_t purpose,
    const uint32_t coinType,
    const uint32_t account,
    const bool change,
    const uint32_t index,
    uint32_t *resultLen)
{
    CKey derivedSecret;
    if ((secretSeedLen < 16) || (secretSeedLen > 64))
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid seed len, len was < 16 or > 64\n");
        *resultLen = -1;
        return nullptr;
    }
    checkSigInit();
    Hd44DeriveChildKey(secretSeed, secretSeedLen, purpose, coinType, account, change, index, derivedSecret, nullptr);
    // no need to CHECK_SIZE for 32
    uint8_t* childKey = (uint8_t*)std::malloc(32);
    std::memcpy(childKey, derivedSecret.begin(), 32);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = 32;
    return childKey;
}

static const std::vector<std::string> descriptionTitles = {"ticker", "name", "url", "hash", "decimals"};

SLAPI uint8_t* parse_group_description(const uint8_t *input, const uint32_t inputLen, uint32_t *resultLen)
{
    std::vector<std::string> vec_desc;
    const CScript script(input, input + inputLen);
    if (!GetTokenDescription(script, vec_desc))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "failed to get token description from the script provided\n");
        *resultLen = -1;
        return nullptr;
    }
    // {} : and ,      (11)
    // 0 is "ticker"    (8)
    // 1 is "name"      (6)
    // 2 is "url"       (5)
    // 3 is "hash"      (6)
    // 4 is "decimals"  (10)

    // for ease of copy, build the json object in a std::string first
    std::string strResult = "{";
    for (size_t i = 0; i < vec_desc.size(); ++i)
    {
        strResult = strResult + "\"" + descriptionTitles[i] + "\":\"" + vec_desc[i] + "\",";
    }
    strResult.pop_back(); // remove final trailing ","
    strResult = strResult + "}";
    const size_t resultSize = strResult.size() + 1; // +1 for \0
    CHECK_SIZE(resultSize);
    uint8_t* result = (uint8_t*)std::malloc(resultSize);
    // copy result into the out buffer
    std::strncpy((char*)result, strResult.c_str(), resultSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = resultSize;
    return result;
}

SLAPI uint8_t* pubkey_to_script_template(const uint8_t *pubkey, const uint32_t pubkeyLen, uint32_t *resultLen)
{
    // CScript P2pktOutput(const CPubKey &pubkey, const CGroupTokenID &group = NoGroup, CAmount grpQuantity = 0);
    const CScript scriptTemplate = P2pktOutput(CPubKey(&pubkey[0], &pubkey[0] + pubkeyLen));
    const size_t scriptTemplateSize = scriptTemplate.size();
    CHECK_SIZE(scriptTemplateSize);
    uint8_t* result = (uint8_t*)std::malloc(scriptTemplateSize);
    std::memcpy(result, &scriptTemplate[0], scriptTemplateSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)scriptTemplateSize;
    return result;
}

#ifdef IOS
#include <Security/Security.h>
// Implement in Android by calling into the java SecureRandom implementation.
// You must provide this Java API
SLAPI uint8_t* random_bytes(const uint32_t num, uint32_t *resultLen)
{
    uint8_t* buf = (uint8_t*)std::malloc(num);
    const int rc = SecRandomCopyBytes(kSecRandomDefault, num, buf);
    if (rc != 0)
    {
        *resultLen = 0;
        return nullptr;
    }
    *resultLen = num;
    return buf;
}
// Implement APIs normally provided by random.cpp calling openssl
uint8_t* get_rand_bytes(const uint32_t num, uint32_t *resultLen)
{
    // it would be dangerous to return if we aren't getting random bytes
    while (1)
    {
        uint8_t* buf = random_bytes(num, resultLen);
        if (*resultLen == num)
        {
            return buf;
        }
        // buf was allocated inside random_bytes but does not contain
        // the correct number of bytes, free it
        free(buf);
        sleep(100);
    }
}
uint8_t* get_strong_rand_bytes(const uint32_t num, uint32_t *resultLen)
{
    // it would be dangerous to return if we aren't getting random bytes
    while (1)
    {
        uint8_t* buf = random_bytes(num, resultLen);
        if (*resultLen == num)
        {
            return buf;
        }
        // buf was allocated inside random_bytes but does not contain
        // the correct number of bytes, free it
        free(buf);
        sleep(100);
    }
}
#endif // IOS

#if !defined(ANDROID) && !defined(IOS)
/** Return random bytes from cryptographically acceptable random sources */
SLAPI uint8_t* random_bytes(const uint32_t num)
{
    if (num > 32)
    {
        set_error(LIBNEXA_ERROR::RETURN_FAILURE, "can only generate up to 32 random bytes at a time \n");
        return nullptr;
    }
    uint8_t* buf = (uint8_t*)std::malloc(num);
    GetStrongRandBytes(buf, num);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return buf;
}

#endif // !defined(ANDROID) && !defined(IOS)

SLAPI uint8_t* recover_pubkey_from_signature(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *sig,
    const uint32_t sigLen,
    uint32_t *resultLen)
{
    checkSigInit();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<uint8_t>(message, message + messageLen);
    const uint256 hash = ss.GetHash();
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying msgHash %s\n", msgHash.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying sigSize %d data %s\n", sig.size, GetHex(sig.data,
    // sig.size).c_str());

    CPubKey pubkey;
    const std::vector<uint8_t> sigv(sig, sig + sigLen);
    if (!pubkey.RecoverCompact(hash, sigv))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "could not recover pubkey from msg and sig data provided\n");
        *resultLen = 0;
        return nullptr;
    }

    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "pkAddr %s\n", pkAddr.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "passedAddr %s\n", passedAddr.GetHex().c_str());
    const size_t sz = pubkey.size();
    CHECK_SIZE(sz);
    uint8_t* result = (uint8_t*)std::malloc(sz);
    std::memcpy(result, pubkey.begin(), sz);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = sz;
    return result;
}

SLAPI uint8_t* serialise_script(const uint8_t *script, const uint32_t scriptLen, uint32_t *resultLen)
{
    std::vector<uint8_t> vec(script, script + scriptLen);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << vec;
    const size_t dataSize = stream.size();
    CHECK_SIZE(dataSize);
    uint8_t* result = (uint8_t*)std::malloc(dataSize);
    std::memcpy(result, stream.data(), dataSize);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)dataSize;
    return result;
}

// result must be 32 bytes
SLAPI uint8_t* sha256(const uint8_t *data, const uint32_t dataLen)
{
    CSHA256 sha;
    sha.Write(data, dataLen);
    uint8_t* result = (uint8_t*)std::malloc(CSHA256::OUTPUT_SIZE);
    sha.Finalize(result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return result;
}

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Since the sighashtype is appended to the signature, more than 64 bytes should be alloced for the result.
*/
SLAPI uint8_t* sign_bch_tx_one_input_using_schnorr(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t hashType,
    const uint8_t *privkey,
    uint32_t *resultLen)
{
    DbgAssert(hashType & BTCBCH_SIGHASH_FORKID, return 0);
    checkSigInit();
    SatoshiTransaction tx;

    CDataStream stream(txData, txData + txDataLen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        stream >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }

    if (inputIndex >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index larger than the tx vin size\n");
        *resultLen = 0;
        return nullptr;
    }

    const CScript priorScript(prevoutScript, prevoutScript + prevoutScriptLen);
    const CKey key = LoadKey(privkey);

    size_t hashes = 0;
    const uint256 sighash = SignatureHashBitcoinCash(priorScript, tx, inputIndex, hashType, inputAmount, &hashes);
    std::vector<uint8_t> sig;
    if (!key.SignSchnorr(sighash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    // CPubKey pub = key.GetPubKey();
    // p("Sign BCH Schnorr: sig: %s, pubkey: %s sighash: %s\n", HexStr(sig).c_str(),
    //    HexStr(pub.begin(), pub.end()).c_str(), sighash.GetHex().c_str());
    sig.push_back(hashType);
    const size_t sigLen = sig.size();
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    result[0] = 0;
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sigLen;
    return result;
}

/** Sign data (compatible with BCH OP_CHECKDATASIG) */
SLAPI uint8_t* sign_hash_ecdsa(const uint8_t *data,
    const uint32_t dataLen,
    const uint8_t *secret,
    uint32_t *resultLen)
{
    checkSigInit();
    const CKey key = LoadKey(secret);
    uint256 hash;
    CSHA256().Write(data, dataLen).Finalize(hash.begin());
    std::vector<uint8_t> sig;
    if (!key.SignECDSA(hash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t sigSize = sig.size();
    CHECK_SIZE(sigSize);
    uint8_t* result = (uint8_t*)std::malloc(sigSize);
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sigSize;
    return result;
}

/** Sign data via the Schnorr signature algorithm.  hash must be 32 bytes.
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.

    The returned signature will not have a sighashtype byte.
*/
SLAPI uint8_t* sign_hash_schnorr(const uint8_t *hash, const uint8_t *privkey, uint32_t *resultLen)
{
    const uint256 sigHash(hash);
    std::vector<uint8_t> sig;
    checkSigInit();

    const CKey key = LoadKey(privkey);

    if (!key.SignSchnorr(sigHash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t sigLen = sig.size();
    if (sigLen > MAX_SIG_LEN) // should never happen for the constant-sized schnorr signatures
    {
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced a Schnorr signature of an invalid size\n");
        *resultLen = 0;
        return nullptr;
    }
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = sigLen;
    return result;
}

SLAPI uint8_t* sign_hash_schnorr_with_nonce(const uint8_t *hash, const uint8_t *privkey, const uint8_t *nonce, uint32_t *resultLen)
{
    const uint256 sigHash(hash);
    std::vector<uint8_t> sig;
    checkSigInit();

    const CKey key = LoadKey(privkey);

    if (!key.SignSchnorrWithNonce(sigHash, nonce, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t sigLen = sig.size();
    if (sigLen > MAX_SIG_LEN) // should never happen for the constant-sized schnorr signatures
    {
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced a Schnorr signature of an invalid size\n");
        *resultLen = 0;
        return nullptr;
    }
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = sigLen;
    return result;
}

SLAPI uint8_t* sign_message(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *secret,
    const uint32_t secretLen,
    uint32_t *resultLen)
{
    if (secretLen != 32)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "secret must be 32 bytes\n");
        resultLen = 0;
        return nullptr;
    }

    checkSigInit();

    const CKey key = LoadKey(secret);
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<uint8_t>(message, message + messageLen);

    const uint256 message_hash = ss.GetHash();
    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing msgHash %s\n", msgHash.GetHex().c_str());
    std::vector<uint8_t> sig;
    if (!key.SignCompact(message_hash, sig)) // signing will only fail if the key is bogus
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    const size_t sigLen = sig.size();
    // check that the size of a returned sig can be represented properly as an int, it should always be
    // CPubKey::COMPACT_SIGNATURE_SIZE
    static_assert(CPubKey::COMPACT_SIGNATURE_SIZE < std::numeric_limits<int>::max());
    if (sigLen != CPubKey::COMPACT_SIGNATURE_SIZE)
    {
        // this will only happen if std::vector::resize() is broken
        // or there is an implementation error in libsecp256k1 that is returning bad
        // ECDSA sigs
        set_error(LIBNEXA_ERROR::INTERNAL_ERROR, "produced an ECDSA signature of an invalid size\n");
        *resultLen = -1;
        return nullptr;
    }
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    // __android_log_print(ANDROID_LOG_INFO, APPNAME, "signing sigSize %d data %s\n", vchSig.size(),
    // GetHex(vchSig.begin(), vchSig.size()).c_str());
    std::memcpy(result, sig.data(), sigLen);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = sigLen;
    return result;
}

/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
    Returns length of returned signature.
*/
SLAPI uint8_t* sign_tx_ecdsa(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t hashType,
    const uint8_t *privkey,
    uint32_t *resultLen)
{
    DbgAssert(hashType & BTCBCH_SIGHASH_FORKID, return 0);
    checkSigInit();
    SatoshiTransaction tx;

    CDataStream stream(txData, txData + txDataLen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        stream >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }
    if (inputIndex >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index is greater than tx vin size\n");
        *resultLen = 0;
        return nullptr;
    }
    const CScript priorScript(prevoutScript, prevoutScript + prevoutScriptLen);
    const CKey key = LoadKey(privkey);

    size_t hashes = 0;
    const uint256 sighash = SignatureHashBitcoinCash(priorScript, tx, inputIndex, hashType, inputAmount, &hashes);
    std::vector<uint8_t> sig;
    if (!key.SignECDSA(sighash, sig))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "data passed in decoded to an invalid key\n");
        *resultLen = 0;
        return nullptr;
    }
    sig.push_back(hashType);
    const size_t sigLen = sig.size();
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    result[0] = 0;
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sigLen;
    return result;
}


/** Sign one input of a transaction
    All buffer arguments should be in binary-serialized data.
    The transaction (txData) must contain the COutPoint (tx hash and vout) of all relevant inputs,
    however, it is not necessary to provide the spend script.
*/
SLAPI uint8_t* sign_tx_one_input_using_schnorr(const uint8_t *txData,
    const uint32_t txDataLen,
    const uint32_t inputIndex,
    const int64_t inputAmount,
    const uint8_t *prevoutScript,
    const uint32_t prevoutScriptLen,
    const uint8_t *hashType,
    const uint32_t hashTypeLen,
    const uint8_t *privkey,
    uint32_t *resultLen)
{
    checkSigInit();
    CTransaction tx;

    SigHashType sigHashType;
    sigHashType.fromBytes(hashType, hashType + hashTypeLen);
    // p("SigHashType vec size: %d, %d, %s(%s): invalid: %d\n", sigHashVec.size(), hashTypeLen,
    //    sigHashType.ToString().c_str(), sigHashType.HexStr().c_str(), sigHashType.isInvalid());

    CDataStream stream(txData, txData + txDataLen, SER_NETWORK, PROTOCOL_VERSION);
    try
    {
        stream >> tx;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "tx data provided failed to decode\n");
        *resultLen = 0;
        return nullptr;
    }

    if (inputIndex >= tx.vin.size())
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "input index larger than tx vin size\n");
        *resultLen = 0;
        return nullptr;
    }

    const CScript priorScript(prevoutScript, prevoutScript + prevoutScriptLen);
    const CKey key = LoadKey(privkey);

    size_t hashes = 0;
    uint256 sigHash;
    if (!SignatureHashNexa(priorScript, tx, inputIndex, sigHashType, sigHash, &hashes))
    {
        *resultLen = 0;
        return nullptr;
    }
    std::vector<uint8_t> sig;
    if (!key.SignSchnorr(sigHash, sig))
    {
        *resultLen = 0;
        return nullptr;
    }
    // p("Sign Schnorr: sig: %s, pubkey: %s sighash: %s\n", HexStr(sig).c_str(), key.GetPubKey().GetHex().c_str(),
    //    sighash.GetHex().c_str());
    sigHashType.appendToSig(sig);
    const size_t sigLen = sig.size();
    CHECK_SIZE(sigLen);
    uint8_t* result = (uint8_t*)std::malloc(sigLen);
    result[0] = 0;
    std::copy(sig.begin(), sig.end(), result);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    *resultLen = (uint32_t)sigLen;
    return result;
}

SLAPI bool verify_block_header(const int32_t chain, const uint8_t *serialisedHeader, const uint32_t serialisedHeaderLen)
{
    checkSigInit();
    const CChainParams *cp = GetChainParams(static_cast<ChainSelector>(chain));
    if (cp == nullptr)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "invalid chain selector\n");
        return false;
    }
    CDataStream stream(serialisedHeader, serialisedHeader + serialisedHeaderLen, SER_NETWORK, PROTOCOL_VERSION);
    CBlockHeader header;
    try
    {
        stream >> header;
    }
    catch (const std::exception &)
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "block header data failed to decode\n");
        return false;
    }
    CValidationState state;
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return CheckBlockHeader(cp->GetConsensus(), header, state, true);
}

SLAPI bool verify_data_schnorr(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *pubkey,
    const uint32_t pubkeyLen,
    const uint8_t *sig) // sig must be 64 bytes
{
    checkSigInit();
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<uint8_t>(message, message + messageLen);
    const uint256 hash = ss.GetHash();
    const CPubKey pk(&pubkey[0], &pubkey[0] + pubkeyLen);
    // If the pubkey is not valid, VerifySchnorr will return false, and an invalid pubkey can never
    // have signed a message.  While for debugging it might be nice to check and return an error
    // this is less efficient, but is placed here commented out for dev debugging.
    // if (!pk.isFullyValid())
    //     set_error(LIBNEXA_ERROR::INVALID_ARG, "bad pubkey\n");
    const std::vector<uint8_t> sigv(sig, sig + 64);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return pk.VerifySchnorr(hash, sigv);
}

SLAPI bool verify_hash_schnorr(const uint8_t *hash,
    const uint8_t *pubkey,
    const uint32_t pubkeyLen,
    const uint8_t *sig) // sig must be 64 bytes
{
    checkSigInit();
    const uint256 messageHash(hash);
    CPubKey pk(&pubkey[0], &pubkey[0] + pubkeyLen);
    // If the pubkey is not valid, VerifySchnorr will return false, and an invalid pubkey can never
    // have signed a message.  While for debugging it might be nice to check and return an error
    // this is less efficient, but is placed here commented out for dev debugging.
    // if (!pk.isFullyValid())
    //     set_error(LIBNEXA_ERROR::INVALID_ARG, "bad pubkey\n");
    const std::vector<uint8_t> sigv(sig, sig + 64);
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    return pk.VerifySchnorr(messageHash, sigv);
}

SLAPI bool verify_message(const uint8_t *message,
    const uint32_t messageLen,
    const uint8_t *addr, // TODO - This is not actually addr but hash160 of pubkey?
    const uint32_t addrLen,
    const uint8_t *sig,
    const uint32_t sigLen)
{
    if (addrLen != 20)
    {
        set_error(LIBNEXA_ERROR::INVALID_ARG, "address must be 20 bytes\n");
        return false;
    }

    checkSigInit();

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic << std::vector<uint8_t>(message, message + messageLen);
    const uint256 hash = ss.GetHash();
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying msgHash %s\n", msgHash.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "verifying sigSize %d data %s\n", sig.size, GetHex(sig.data,
    // sig.size).c_str());

    CPubKey pubkey;
    const std::vector<uint8_t> sigv(sig, sig + sigLen);
    if (!pubkey.RecoverCompact(hash, sigv))
    {
        set_error(LIBNEXA_ERROR::DECODE_FAILURE, "could not recover pubkey from msg and sig data provided\n");
        return false;
    }

    const CKeyID pkAddr = pubkey.GetID();
    const CKeyID passedAddr = CKeyID(uint160(addr));
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "pkAddr %s\n", pkAddr.GetHex().c_str());
    //__android_log_print(ANDROID_LOG_INFO, APPNAME, "passedAddr %s\n", passedAddr.GetHex().c_str());
    set_error(LIBNEXA_ERROR::SUCCESS_NO_ERROR, "");
    if (pkAddr == passedAddr)
    {
        return true;
    }
    else
    {
        return false;
    }
}
