// Copyright (c) 2022-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTIL_GROUP_TOKEN_H
#define UTIL_GROUP_TOKEN_H

#include "consensus/grouptokens.h"

static const unsigned int LEGACY_TOKEN_OP_RETURN_GROUP_ID = 88888888;
static const unsigned int LEGACY_NFT_OP_RETURN_GROUP_ID = 88888889;

// NRC-1 Token
static const unsigned int NRC1_OP_RETURN_GROUP_ID = 88888890;
// NRC-2 NFT Collection
static const unsigned int NRC2_OP_RETURN_GROUP_ID = 88888891;
// NRC-3 NFT
static const unsigned int NRC3_OP_RETURN_GROUP_ID = 88888892;


struct CAuth
{
    int nMint = 0;
    int nMelt = 0;
    int nRenew = 0;
    int nRescript = 0;
    int nSubgroup = 0;
};

// Retrieve token descriptions using an OP_RETURN
bool GetTokenDescription(const CScript &script, std::vector<std::string> &_vDesc);

#endif // UTIL_GROUP_TOKEN_H
