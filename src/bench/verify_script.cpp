// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2016-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "key.h"
#if defined(HAVE_CONSENSUS_LIB)
#include "script/bitcoinconsensus.h"
#endif
#include "consensus/validation.h"
#include "script/script.h"
#include "script/sign.h"
#include "streams.h"

#include <array>

// FIXME: Dedup with BuildCreditingTransaction in test/script_tests.cpp.
static CMutableTransaction BuildCreditingTransaction(const CScript &scriptPubKey)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 0;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].amount = 1;
    txCredit.vin[0].scriptSig = CScript() << CScriptNum::fromIntUnchecked(0) << CScriptNum::fromIntUnchecked(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = 1;

    return txCredit;
}

static void VerifyNestedIfScript(benchmark::State &state)
{
    Stack stack;
    CScript script;
    for (int i = 0; i < 100; ++i)
    {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i)
    {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i)
    {
        script << OP_ENDIF;
    }
    while (state.KeepRunning())
    {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, MAX_OPS_PER_SCRIPT, ScriptImportedState(), &error);
        assert(ret);
    }
}
BENCHMARK(VerifyNestedIfScript, 100);
