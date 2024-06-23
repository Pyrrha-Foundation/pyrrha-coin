// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/interpreter.h>
#include <script/script.h>

#include <test/test_nexa.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(op_convert_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(op_convert)
{
    auto flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis; // no imported state
    ScriptError error;
    bool ret;

    // fail, no count argument
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          OP_CONVERT;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // fail, no data
    {
        CScript scriptSig = CScript();
        CScript scriptPubKey = CScript() <<
          OP_1 << OP_CONVERT;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // fail, 2 chunks expected, 1 chunk provided
    {
        CScript scriptSig = CScript() << ParseHex("02f00d");
        CScript scriptPubKey = CScript() <<
          OP_2 << OP_NEGATE << OP_CONVERT <<
          ParseHex("f00d") << OP_EQUALVERIFY <<
          ParseHex("beef") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_INVALID_NUMBER_RANGE);
    }

    // fail, 2 items expected to encode, 1 item on stack provided
    {
        CScript scriptSig = CScript() << OP_1;
        CScript scriptPubKey = CScript() <<
          OP_2 << OP_CONVERT <<
          ParseHex("02f00d02beef") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(!ret);
        BOOST_CHECK(error == SCRIPT_ERR_STACK_SIZE);
    }

    // ok, 0, special case - parse data until end, push number of items parsed
    {
        CScript scriptSig = CScript() << ParseHex("02f00d02beef02feed");
        CScript scriptPubKey = CScript() <<
          OP_0 << OP_CONVERT <<
          OP_3 << OP_EQUALVERIFY <<
          ParseHex("feed") << OP_EQUALVERIFY <<
          ParseHex("beef") << OP_EQUALVERIFY <<
          ParseHex("f00d") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, -3, parse 3 items from data
    {
        CScript scriptSig = CScript() << ParseHex("02f00d02beef02feed");
        CScript scriptPubKey = CScript() <<
          OP_3 << OP_NEGATE << OP_CONVERT <<
          ParseHex("feed") << OP_EQUALVERIFY <<
          ParseHex("beef") << OP_EQUALVERIFY <<
          ParseHex("f00d") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, -1, parse 1 item from data, unparsed remainder is left on top of the stack
    {
        CScript scriptSig = CScript() << ParseHex("02f00d02beef02feed");
        CScript scriptPubKey = CScript() <<
          OP_1NEGATE << OP_CONVERT <<
          ParseHex("02beef02feed") << OP_EQUALVERIFY <<
          ParseHex("f00d") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, 4, number primitives, string data
    {
        CScript scriptSig = CScript() << OP_1 << OP_0 << OP_1NEGATE << ToByteVector(std::string("AB"));
        CScript scriptPubKey = CScript() <<
          OP_4 << OP_CONVERT <<
          ParseHex("0241424f0051") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, 2 items out of 3 are encoded, 1 is left on stack
    {
        CScript scriptSig = CScript() << OP_1 << OP_0 << ToByteVector(std::string("AB"));
        CScript scriptPubKey = CScript() <<
          OP_2 << OP_CONVERT <<
          ParseHex("02414200") << OP_EQUALVERIFY <<
          OP_1 << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, 1 item out of 3 is encoded, 2 are left on stack
    {
        CScript scriptSig = CScript() << OP_1 << OP_0 << ToByteVector(std::string("AB"));
        CScript scriptPubKey = CScript() <<
          OP_1 << OP_CONVERT <<
          ParseHex("024142") << OP_EQUALVERIFY <<
          OP_0 << OP_EQUALVERIFY <<
          OP_1 << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }

    // ok, 0, inversion of OP_CONVERT results in the inverted data
    {
        CScript scriptSig = CScript() << ParseHex("02f00d02beef02feed");
        CScript scriptPubKey = CScript() <<
          OP_0 << OP_CONVERT <<
          OP_CONVERT <<
          ParseHex("02feed02beef02f00d") << OP_EQUALVERIFY <<
          OP_TRUE;

        ret = VerifyScript(scriptSig, scriptPubKey, flags, sis, &error);
        BOOST_CHECK(ret);
    }
}

BOOST_AUTO_TEST_SUITE_END()