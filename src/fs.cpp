// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "fs.h"

#include <cstring>
#include <filesystem>

namespace fsbridge {

#ifdef WIN32
    #include <stringapiset.h>
    std::wstring charToWstring(const char *cstr)
    {
        const size_t length = std::strlen(cstr);
        const int requiredSize = MultiByteToWideChar(CP_UTF8, 0, cstr, length, NULL, 0);
        std::wstring wstr(requiredSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, cstr, length, &wstr[0], requiredSize);
        return wstr;
    }

    std::wstring stringToWstring(const std::string str)
    {
        const char* cstr = str.c_str();
        return charToWstring(cstr);
    }

    std::string wcharToString(const wchar_t *wcstr)
    {
        const size_t length = std::wcslen(wcstr);
        const int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wcstr, length, NULL, 0, NULL, NULL);
        std::string str(requiredSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, wcstr, length, &str[0], requiredSize, NULL, NULL);
        return str;
    }

    std::string wstringToString(const std::wstring wstr)
    {
        const wchar_t* wcstr = wstr.c_str();
        return wcharToString(wcstr);
    }
#endif

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
