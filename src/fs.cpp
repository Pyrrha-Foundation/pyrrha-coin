// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "fs.h"

#include <cstring>
#include <filesystem>

#ifdef WIN32
#include <stringapiset.h>
std::wstring charToWstring(const char *cstr)
{
    const size_t length = std::strlen(cstr);
    const int count = MultiByteToWideChar(CP_ACP, 0, cstr, length, NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, cstr, length, &wstr[0], count);
    return wstr;
}
#endif

namespace fsbridge {

FILE *fopen(const fs::path& p, const char *mode)
{
#ifdef WIN32
    // note: this conversion to wstring only works because the mode is ansii chars
    std::wstring wmode = charToWstring(mode);
    return ::_wfopen(p.wstring().c_str(), wmode.c_str());
#else
    return ::fopen(p.string().c_str(), mode);
#endif
}

FILE *freopen(const fs::path& p, const char *mode, FILE *stream)
{
#ifdef WIN32
    std::wstring wmode = charToWstring(mode);
    return ::_wfreopen(p.wstring().c_str(), wmode.c_str(), stream);
#else
    return ::freopen(p.string().c_str(), mode, stream);
#endif
}

} // fsbridge
