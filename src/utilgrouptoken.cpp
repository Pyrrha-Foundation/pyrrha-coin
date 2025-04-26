// Copyright (c) 2022-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utilgrouptoken.h"

#include <cctype>

void ParseLegacyTokenDescription(const CScript &script, std::vector<std::string> &_vDesc, CScript::const_iterator &pc)
{
    opcodetype op;
    std::vector<unsigned char> vchRet;
    // Get labels
    int count = 0;
    while (script.GetOp(pc, op, vchRet))
    {
        if (op != OP_0)
        {
            if (count < 4)
            {
                if (count == 3)
                {
                    // Convert hash stored as a vector of unsigned chars to a string.
                    uint256 hash(&vchRet.data()[0]);
                    _vDesc.push_back(hash.ToString());
                }
                else
                {
                    std::string s(vchRet.begin(), vchRet.end());
                    _vDesc.push_back(s);
                }
            }
            else if (count == 4) // 5th parameter in op return is the number of decimals
            {
                uint8_t amt;
                if (0 <= op && op <= OP_PUSHDATA4)
                {
                    amt = CScriptNum(vchRet, false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
                }
                else if (op == 0)
                    amt = 0;
                else
                    amt = op - OP_1 + 1;
                _vDesc.push_back(std::to_string(amt));
            }
        }
        else
        {
            _vDesc.push_back(std::string(""));
        }

        count++;
    }

    if (!_vDesc.empty())
    {
        while (_vDesc.size() < 4)
        {
            _vDesc.push_back("");
        }
        while (_vDesc.size() < 5)
        {
            _vDesc.push_back("0");
        }
    }
    else
    {
        std::vector<std::string> vEmptyDesc{"", "", "", "", "0"};
        _vDesc.swap(vEmptyDesc);
    }
}

bool is_alphanumeric(const std::string &str) { return std::all_of(str.begin(), str.end(), ::isalnum); }

bool ParseNRC1and2Description(const CScript &script, std::vector<std::string> &_vDesc, CScript::const_iterator &pc)
{
    opcodetype op;
    std::vector<unsigned char> vchRet;

    // get the ticker
    script.GetOp(pc, op, vchRet);
    std::string str_ticker(vchRet.begin(), vchRet.end());
    if ((str_ticker.size() < 2) || (str_ticker.size() > 8) || (is_alphanumeric(str_ticker) == false))
    {
        // ticker size can not be less than 2 or greater than 8
        // ticker can only contain alpha numeric chars
        return false;
    }
    _vDesc.push_back(str_ticker);

    // get the name
    script.GetOp(pc, op, vchRet);
    std::string str_name(vchRet.begin(), vchRet.end());
    if (str_name.size() < 2 || str_name.size() > 25)
    {
        // name size can not be less than 2 or greater than 25
        return false;
    }
    _vDesc.push_back(str_name);

    // get the url
    script.GetOp(pc, op, vchRet);
    std::string str_url(vchRet.begin(), vchRet.end());
    // TODO - validate the URL is valid?
    _vDesc.push_back(str_url);

    // get the hash
    script.GetOp(pc, op, vchRet);
    if (vchRet.size() != 32)
    {
        // hash size must be 32
        return false;
    }
    uint256 hash(&vchRet.data()[0]);
    _vDesc.push_back(hash.ToString());

    // get the decimals
    script.GetOp(pc, op, vchRet);
    uint8_t amt;
    if (0 <= op && op <= OP_PUSHDATA4)
    {
        amt = CScriptNum(vchRet, false, CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT).getint64();
    }
    else
    {
        amt = op - OP_1 + 1;
    }
    if (amt > 18)
    {
        // decimals must fall in the range of 0 to 18
        return false;
    }
    _vDesc.push_back(std::to_string(amt));
    return true;
}

bool ParseNRC3Description(const CScript &script, std::vector<std::string> &_vDesc, CScript::const_iterator &pc)
{
    opcodetype op;
    std::vector<unsigned char> vchRet;
    // get the url
    script.GetOp(pc, op, vchRet);
    std::string str_url(vchRet.begin(), vchRet.end());
    // TODO - validate the URL is valid?
    _vDesc.push_back(str_url);

    // get the hash
    script.GetOp(pc, op, vchRet);
    if (vchRet.size() != 32)
    {
        // hash size must be 32
        return false;
    }
    uint256 hash(&vchRet.data()[0]);
    _vDesc.push_back(hash.ToString());
    return true;
}

bool GetTokenDescription(const CScript &script, std::vector<std::string> &_vDesc)
{
    _vDesc.clear();

    CScript::const_iterator pc = script.begin();
    opcodetype op;
    std::vector<unsigned char> vchRet;

    // Check we have an op_return
    script.GetOp(pc, op, vchRet);
    if (op != OP_RETURN)
    {
        return false;
    }

    // Check for correct group id
    script.GetOp(pc, op, vchRet);
    uint32_t grpId;
    std::stringstream ss;
    std::reverse(vchRet.begin(), vchRet.end());
    ss << std::hex << HexStr(vchRet);
    ss >> grpId;

    // NRC1 and NRC2 OP_RETURN data is the same, the difference between
    // the two is in the off chain data
    if (grpId == NRC1_OP_RETURN_GROUP_ID || grpId == NRC2_OP_RETURN_GROUP_ID)
    {
        bool ret = ParseNRC1and2Description(script, _vDesc, pc);
        if (!ret)
        {
            _vDesc.clear();
        }
        return ret;
    }
    else if (grpId == NRC3_OP_RETURN_GROUP_ID)
    {
        bool ret = ParseNRC3Description(script, _vDesc, pc);
        if (!ret)
        {
            _vDesc.clear();
        }
        return ret;
    }
    else if (grpId == LEGACY_TOKEN_OP_RETURN_GROUP_ID)
    {
        ParseLegacyTokenDescription(script, _vDesc, pc);
        return true;
    }
    return false;
}
