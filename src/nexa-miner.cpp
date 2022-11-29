// Copyright (c) 2018-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#if defined(HAVE_CONFIG_H)
#include "nexa-config.h"
#endif

#include "CL/cl.h"

#include "allowed_args.h"
#include "arith_uint256.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "consensus/params.h"
#include "fs.h"
#include "hashwrapper.h"
#include "key.h"
#include "pow.h"
#include "primitives/block.h"
#include "pubkey.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "sync.h"
#include "util.h"
#include "utilstrencodings.h"

#include <cstdlib>
#include <functional>
#include <random>
#include <stdio.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <univalue.h>

// below two require C++11
#include <functional>
#include <random>

#include "secp256k1.cl"

#ifdef DEBUG_LOCKORDER
std::atomic<bool> lockdataDestructed{false};
LockData lockdata;
#endif

#define secp256k1_precomp	0
#define secp256k1_pj		1
#define secp256k1_pubkey	2
#define secp256k1_pubkey2	3
#define secp256k1_hashOut	4

uint32_t g_rawIntensity = 1 << 18;

// secp256k1 stuff
uint32_t g_curveBits = 20;
void *g_secp256k1_precompute_20 = nullptr;
void *g_secp256k1_gej_temp = nullptr;
void *g_secp256k1_z_ratio = nullptr;

// opencl stuff
#ifndef MAX_GPUS
    #define MAX_GPUS 16
#endif

enum _kernel
{
    kernel_sha256_64 = 0,
    kernel_sha256_40,
    kernel_sha256_32,
    kernel_nexapow_start,
	kernel_nexapow,
    kernel_secp256k1_64,
    kernel_checkhash_64,
    kernel_count
};

bool                g_isNvidia[MAX_GPUS];
cl_device_id        g_deviceId[MAX_GPUS];
cl_context          g_deviceContext[MAX_GPUS];
cl_command_queue    g_deviceCommandQueue[MAX_GPUS];

cl_mem              g_bufferInput[MAX_GPUS];
cl_mem              g_bufferOutput[MAX_GPUS];
cl_mem              g_bufferTarget[MAX_GPUS];
cl_mem              g_bufferHash[MAX_GPUS];
cl_mem              g_bufferExtra[MAX_GPUS][8];

cl_program          g_program[MAX_GPUS];
cl_kernel           g_kernels[MAX_GPUS][kernel_count];

uint32_t            g_nonces[MAX_GPUS];

#define SET_KERNEL_ARG_GPU( _gpuId, _kernel, _id, _size, _arg ) \
	if ( ( ret = clSetKernelArg( g_kernels[ _gpuId ][ _kernel ], _id, _size, _arg ) ) != CL_SUCCESS )\
	{\
		printf( "GPU[#%i]: failed to set parameter %i for kernel %i\n", _gpuId, _id, _kernel );\
	}\

#ifdef _WIN32
#include <windows.h>

static inline void port_sleep( size_t msec )
{
    Sleep( (DWORD)msec );
}
#else
#include <unistd.h>

static inline void port_sleep( size_t msec )
{
  usleep( msec * 1000 );
}
#endif

cl_int multiRunJob64( uint32_t gpuId, _kernel kernel, cl_mem inputBuffer, cl_mem hashBuffer, uint32_t startNonce = 0 )
{
    cl_int ret = CL_SUCCESS;

	SET_KERNEL_ARG_GPU( gpuId, kernel, 0, sizeof(cl_mem), &inputBuffer );
	SET_KERNEL_ARG_GPU( gpuId, kernel, 1, sizeof(cl_mem), &hashBuffer );
	SET_KERNEL_ARG_GPU( gpuId, kernel, 2, sizeof(cl_mem), nullptr );
    uint32_t maxIntensity = g_rawIntensity;
    SET_KERNEL_ARG_GPU( gpuId, kernel, 3, sizeof(cl_uint), &maxIntensity );

    size_t offset = startNonce;
    size_t intensity = g_rawIntensity;
    size_t workSize = 64;
	if ( ( ret = clEnqueueNDRangeKernel( g_deviceCommandQueue[ gpuId ], g_kernels[ gpuId ][ kernel ], 1, offset ? &offset : nullptr, &intensity, &workSize, 0, nullptr, nullptr ) ) != CL_SUCCESS )
	{
		printf( "GPU[#%i] failed on clEnqueueNDRangeKernel for kernel %i\n", gpuId, kernel );
		return -1;
	}

	return CL_SUCCESS;
}

cl_int multiCheckHash( uint32_t gpuId, cl_mem buffer )
{
    cl_int ret = CL_SUCCESS;
	cl_event eventFinish;

	SET_KERNEL_ARG_GPU( gpuId, kernel_checkhash_64, 0, sizeof(cl_mem), &buffer );
	SET_KERNEL_ARG_GPU( gpuId, kernel_checkhash_64, 1, sizeof(cl_mem), &g_bufferOutput[ gpuId ] );
    SET_KERNEL_ARG_GPU( gpuId, kernel_checkhash_64, 2, sizeof(cl_ulong), &g_bufferTarget[ gpuId ] );
    uint32_t maxIntensity = g_rawIntensity;
    SET_KERNEL_ARG_GPU( gpuId, kernel_checkhash_64, 3, sizeof(cl_uint), &maxIntensity );

    size_t intensity = g_rawIntensity;
    size_t workSize = 64;
	if ( ( ret = clEnqueueNDRangeKernel( g_deviceCommandQueue[ gpuId ], g_kernels[ gpuId ][ kernel_checkhash_64 ], 1, nullptr, &intensity, &workSize, 0, nullptr, &eventFinish ) ) != CL_SUCCESS )
	{
		printf( "GPU[#%i] failed on clEnqueueNDRangeKernel for kernel %i\n", gpuId, kernel_checkhash_64 );
		return -1;
	}

    if ( g_isNvidia[ gpuId ] )
    {
        clFlush( g_deviceCommandQueue[ gpuId ] );

        cl_int evenStatus;
        do
        {
            clGetEventInfo( eventFinish, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &evenStatus, nullptr );
            if ( evenStatus > CL_COMPLETE ) port_sleep( 1 );
        }
        while ( evenStatus > CL_COMPLETE ) ;
        clReleaseEvent( eventFinish );
        eventFinish = nullptr;
    }
    else
    {
        clWaitForEvents( 1, &eventFinish );
    }
    clReleaseEvent( eventFinish );

	return CL_SUCCESS;
}

// Lambda used to generate entropy, per-thread (see CpuMiner, et al below)
typedef std::function<uint32_t(void)> RandFunc;

CCriticalSection cs_commitment;
uint256 g_headerCommitment;
uint32_t g_nBits = 0;
UniValue g_id;
bool deterministicStartCount = false;

CCriticalSection cs_blockhash;
uint256 bestBlockHash;

std::string minerName;

int CpuMiner(int threadNum);

using namespace std;

std::mutex nowLock;
std::string now()
{
    nowLock.lock();
    std::time_t now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char *tmp = std::ctime(&now_time);
    std::string ret(tmp, tmp + strlen(tmp) - 1);
    nowLock.unlock();
    return ret;
}

class Secp256k1Init
{
    ECCVerifyHandle globalVerifyHandle;

public:
    Secp256k1Init() { ECC_Start(); }
    ~Secp256k1Init() { ECC_Stop(); }
};

class NexaMinerArgs : public AllowedArgs::NexaCli
{
public:
    NexaMinerArgs(CTweakMap *pTweaks = nullptr)
    {
        addHeader(_("Mining options:"))
            .addArg("blockversion=<n>", ::AllowedArgs::requiredInt,
                _("Set the block version number. For testing only. Value must be an integer"))
            .addArg("cpus=<n>", ::AllowedArgs::requiredInt,
                _("Number of cpus to use for mining (default: 1). Value must be an integer"))
            .addArg("duration=<n>", ::AllowedArgs::requiredInt,
                _("Number of seconds to mine a particular block candidate (default: 30). Value must be an integer"))
            .addArg("nblocks=<n>", ::AllowedArgs::requiredInt,
                _("Number of blocks to mine (default: mine forever / -1). Value must be an integer"))
            .addArg("coinbasesize=<n>", ::AllowedArgs::requiredInt,
                _("Get a fixed size coinbase Tx (default: do not use / 0). Value must be an integer"))
            // requiredAmount here validates a float
            .addArg("maxdifficulty=<f>", ::AllowedArgs::requiredAmount,
                _("Set the maximum difficulty (default: no maximum) we will mine. If difficulty exceeds this value we "
                  "sleep and poll every <duration> seconds until difficulty drops below this threshold. Value must be "
                  "a float or integer"))
            .addArg("address=<string>", ::AllowedArgs::requiredStr,
                _("The address to send the newly generated nexa to. If omitted, will default to an address in the "
                  "nexa daemon's wallet."))
            .addArg("name=<string>", ::AllowedArgs::requiredStr,
                _("Name for this mining machine for statistics tracking in the full node"))
            .addArg("deterministic[=boolean]", ::AllowedArgs::optionalBool,
                _("Instead of starting at a random nonce, start with 0x0N000001, where N is the thread number."
                  "  Default is false."));
    }
};


/*
static CBlockHeader CpuMinerJsonToHeader(const UniValue &params)
{
    // Does not set hashMerkleRoot (Does not exist in Mining-Candidate params).
    CBlockHeader blockheader;

    // hashPrevBlock
    string tmpstr = params["prevhash"].get_str();
    std::vector<unsigned char> vec = ParseHex(tmpstr);
    std::reverse(vec.begin(), vec.end()); // sent reversed
    blockheader.hashPrevBlock = uint256(vec);

    // nTime:
    blockheader.nTime = params["time"].get_int();

    // nBits
    {
        std::stringstream ss;
        ss << std::hex << params["nBits"].get_str();
        ss >> blockheader.nBits;
    }

    return blockheader;
}
*/

void static MinerThread(int threadNum)
{
    while (1)
    {
        try
        {
            CpuMiner(threadNum);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "CommandLineRPC()");
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
        }
    }
}

static bool CpuMinerJsonToData(const UniValue &params, uint256 &headerCommitment, uint32_t &nBits, UniValue &id)
{
    string tmpstr;
    tmpstr = params["headerCommitment"].get_str();
    std::vector<unsigned char> vec = ParseHex(tmpstr);
    std::reverse(vec.begin(), vec.end()); // sent reversed
    headerCommitment = uint256(vec);

    // nBits
    {
        std::stringstream ss;
        ss << std::hex << params["nBits"].get_str();
        ss >> nBits;
    }

    id = params["id"];

    return true;
}

static bool CpuMineBlockHasherNextChain(int &ntries,
    uint256 headerCommitment,
    uint32_t nBits,
    const RandFunc &randFunc,
    const Consensus::Params &conp,
    uint32_t &count,
    uint32_t rollAt,
    uint32_t extra,
    std::vector<unsigned char> &nonce)
{
    arith_uint256 hashTarget = arith_uint256().SetCompact(nBits);
    bool found = false;

    uint256 target;
    target.SetHex(hashTarget.GetHex());
    printf( "target: %s\tstartNonce: %u\n", target.GetHex().c_str(), g_nonces[extra] );
    clEnqueueWriteBuffer( g_deviceCommandQueue[ extra ], g_bufferTarget[ extra ], CL_TRUE, 0, 32, &target.begin()[ 0 ], 0, nullptr, nullptr );

    std::vector<uint32_t> hash;
    hash.resize(11);
    for ( int i = 0; i < 9; i++ ) hash[ i ] = 0;
    memcpy( &hash[0], headerCommitment.begin(), 32 );
    ((uint8_t*)&hash[8])[0] = 8;

    clEnqueueWriteBuffer( g_deviceCommandQueue[ extra ], g_bufferInput[ extra ], CL_TRUE, 0, 11 * sizeof(cl_uint), &hash[ 0 ], 0, nullptr, nullptr );

    cl_ulong zero = 0;
    clEnqueueWriteBuffer( g_deviceCommandQueue[ extra ], g_bufferOutput[ extra ], CL_TRUE, 0, sizeof(cl_ulong), &zero, 0, nullptr, nullptr );

    /* Eventually when hashing performance improved dramatically we may need to start with 6 bytes.

    // Note that since I have a coinbase that is unique to my hashing effort, my hashing won't duplicate a competitor's
    // efforts.  And a new candidate is generated every 30 seconds, so my hashing won't conflict with my earlier self.
    // So it does not matter that we all start with few nonce bits.
    if (nonce.size() < 6) nonce.resize(6);

    //uint32_t startCount = randFunc();
    nonce[4] = extra & 255;
    nonce[5] = (extra >> 8) & 255;
    */

    if (nonce.size() < 8)
        nonce.resize(8);

    for ( int i = 0; i < 8; i++ )
        nonce[i] = 0;//randFunc();

    uint32_t startNonce = g_nonces[extra];

    while (!found)
    {
        // Search
        while (!found)
        {
            uint256 miningHash;

            cl_int ret = 0;

            SET_KERNEL_ARG_GPU( extra, kernel_secp256k1_64, 4, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_pj ] );	
            SET_KERNEL_ARG_GPU( extra, kernel_secp256k1_64, 5, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_precomp ] );
            SET_KERNEL_ARG_GPU( extra, kernel_secp256k1_64, 6, sizeof(cl_uint), &g_curveBits );

            SET_KERNEL_ARG_GPU( extra, kernel_nexapow_start, 4, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_pj ] );	
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow_start, 5, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_precomp ] );
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow_start, 6, sizeof(cl_uint), &g_curveBits );

            SET_KERNEL_ARG_GPU( extra, kernel_nexapow, 4, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_pubkey ] );
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow, 5, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_pubkey2 ] );
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow, 6, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_pj ] );	
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow, 7, sizeof(cl_mem), &g_bufferExtra[ extra ][ secp256k1_precomp ] );
            SET_KERNEL_ARG_GPU( extra, kernel_nexapow, 8, sizeof(cl_uint), &g_curveBits );

            multiRunJob64( extra, kernel_sha256_40, g_bufferInput[ extra ], g_bufferHash[ extra ], startNonce );
#ifdef GPU_VERIFY_STEPS
            {
                uint32_t verify[16];
                clEnqueueReadBuffer( g_deviceCommandQueue[ extra ], g_bufferHash[ extra ], CL_TRUE, 0, 16 * sizeof(cl_uint), &verify[ 0 ], 0, nullptr, nullptr );
                memcpy( miningHash.begin(), verify, 32 );
                printf( "hash sha256 gpu: %s\n", miningHash.GetHex().c_str() );
            }
#endif

            multiRunJob64( extra, kernel_sha256_32, g_bufferHash[ extra ], g_bufferHash[ extra ] );

#ifdef GPU_VERIFY_STEPS
            {
                uint32_t verify[16];
                clEnqueueReadBuffer( g_deviceCommandQueue[ extra ], g_bufferHash[ extra ], CL_TRUE, 0, 16 * sizeof(cl_uint), &verify[ 0 ], 0, nullptr, nullptr );
                memcpy( miningHash.begin(), verify, 32 );
                printf( "hash mid256 gpu: %s\n", miningHash.GetHex().c_str() );
            }
#endif

            multiRunJob64( extra, kernel_secp256k1_64, g_bufferHash[ extra ], g_bufferExtra[ extra ][ secp256k1_pubkey ] );

            multiRunJob64( extra, kernel_nexapow_start, g_bufferHash[ extra ], g_bufferExtra[ extra ][ secp256k1_pubkey2 ] );

            multiRunJob64( extra, kernel_nexapow, g_bufferHash[ extra ], g_bufferExtra[ extra ][ secp256k1_hashOut ] );

            multiRunJob64( extra, kernel_sha256_64, g_bufferExtra[ extra ][ secp256k1_hashOut ], g_bufferExtra[ extra ][ secp256k1_hashOut ] );

#ifdef GPU_VERIFY_STEPS
            {
                uint32_t verify[16];
                clEnqueueReadBuffer( g_deviceCommandQueue[ extra ], g_bufferExtra[ extra ][ secp256k1_hashOut ], CL_TRUE, 0, 16 * sizeof(cl_uint), &verify[ 0 ], 0, nullptr, nullptr );
                memcpy( miningHash.begin(), verify, 32 );
                printf( "hash final gpu: %s\n", miningHash.GetHex().c_str() );
            }
#endif

            multiCheckHash( extra, g_bufferExtra[ extra ][ secp256k1_hashOut ] );

            uint64_t nonces[32];
            clEnqueueReadBuffer( g_deviceCommandQueue[ extra ], g_bufferOutput[ extra ], CL_TRUE, 0, 32 * sizeof(cl_ulong), &nonces[ 0 ], 0, nullptr, nullptr );
            clEnqueueWriteBuffer( g_deviceCommandQueue[ extra ], g_bufferOutput[ extra ], CL_TRUE, 0, sizeof(cl_ulong), &zero, 0, nullptr, nullptr );

            for ( uint64_t i = 0; i < ( nonces[ 0 ] <= 16 ? nonces[ 0 ] : 16 ); i++ )
            {
                ((uint32_t*)&nonce[4])[0] = startNonce + nonces[ i + 1 ];

                miningHash = GetMiningHash(headerCommitment, nonce);
                if (CheckProofOfWork(miningHash, nBits, conp))
                {
                    g_nonces[ extra ] = 0;
                    // Found a solution
                    found = true;
                    printf("%s: proof-of-work found  \n  mining puzzle solution: %s  \ntarget: %s\n", now().c_str(),
                        miningHash.GetHex().c_str(), hashTarget.GetHex().c_str());
                    return found;
                }
            }

            g_nonces[ extra ] += g_rawIntensity;
            ntries -= (int)g_rawIntensity;
            if (ntries < 1)
            {
                return false; // Give up leave
            }
        }
    }

    return found;
}

static double GetDifficulty(uint32_t nBits)
{
    int nShift = (nBits >> 24) & 0xff;

    double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

// trvially-constructible/copyable info for use in CpuMineBlock below to check if mining a stale block
struct BlkInfo
{
    uint64_t prevCheapHash = 0;
    uint32_t nBits = 0;
};
// Thread-safe version of above for the shared variable. We do it this way
// because std::atomic<struct> isn't always available on all platforms.
class SharedBlkInfo : protected BlkInfo
{
    mutable CCriticalSection lock;

public:
    void store(const BlkInfo &o)
    {
        LOCK(lock);
        prevCheapHash = o.prevCheapHash;
        nBits = o.nBits;
    }
    bool operator==(const BlkInfo &o) const
    {
        LOCK(lock);
        return prevCheapHash == o.prevCheapHash && nBits == o.nBits;
    }
};
// shared variable: used to inform all threads when the latest block or difficulty has changed
static SharedBlkInfo sharedBlkInfo;

static UniValue CpuMineBlock(unsigned int searchDuration, bool &found, const RandFunc &randFunc, int threadNum)
{
    UniValue ret(UniValue::VARR);
    const double maxdiff = GetDoubleArg("-maxdifficulty", 0.0);
    searchDuration *= 1000; // convert to millis
    found = false;

    uint256 headerCommitment;
    uint32_t nBits = 0;
    UniValue id;
    {
        LOCK(cs_commitment);
        headerCommitment = g_headerCommitment;
        nBits = g_nBits;
        id = g_id;
    }
    if (!nBits)
    {
        MilliSleep(1000);
        return ret;
    }

    // first check difficulty, and abort if it's lower than maxdifficulty from CLI
    const double difficulty = GetDifficulty(nBits);
    if (maxdiff > 0.0 && difficulty > maxdiff)
    {
        printf("Current difficulty: %3.2f > maxdifficulty: %3.2f, sleeping for %d seconds...\n", difficulty, maxdiff,
            searchDuration / 1000);
        MilliSleep(searchDuration);
        return ret;
    }

    // ok, difficulty check passed or not applicable, proceed
#if 0
    UniValue tmp(UniValue::VOBJ);
    string tmpstr;
    std::vector<uint256> merkleproof;
    vector<unsigned char> coinbaseBytes(ParseHex(params["coinbase"].get_str()));


    // re-create merkle branches:
    {
        UniValue uvMerkleproof = params["merkleProof"];
        for (unsigned int i = 0; i < uvMerkleproof.size(); i++)
        {
            tmpstr = uvMerkleproof[i].get_str();
            std::vector<unsigned char> mbr = ParseHex(tmpstr);
            std::reverse(mbr.begin(), mbr.end());
            merkleproof.push_back(uint256(mbr));
        }
    }
#endif

    const CChainParams &cparams = Params();
    auto conp = cparams.GetConsensus();

    printf("%s: Mining: id: %x headerCommitment: %s bits: %x difficulty: %3.4f\n", now().c_str(),
        (unsigned int)id.get_int64(), headerCommitment.ToString().c_str(), nBits, difficulty);

    int64_t start = GetTimeMillis();
    std::vector<unsigned char> nonce;
    int ChunkAmt = 10000;
    int checked = 0;
    uint32_t startCount = 1;
    if (!deterministicStartCount)
        startCount = randFunc();
    uint32_t rollAt = startCount - 1;
    const BlkInfo blkInfo = {headerCommitment.GetCheapHash(), nBits};

    while ((GetTimeMillis() < start + searchDuration) && !found && sharedBlkInfo == blkInfo)
    {
        // When mining mainnet, you would normally want to advance the time to keep the block time as close to the
        // real time as possible.  However, this CPU miner is only useful on testnet and in testnet the block difficulty
        // resets to 1 after 20 minutes.  This will cause the block's difficulty to mismatch the expected difficulty
        // and the block will be rejected.  So do not advance time (let it be advanced by nexad every time we
        // request a new block).
        // header.nTime = (header.nTime < GetTime()) ? GetTime() : header.nTime;
        int tries = g_rawIntensity;
        found = CpuMineBlockHasherNextChain(
            tries, headerCommitment, nBits, randFunc, conp, startCount, rollAt, threadNum, nonce);
        checked += g_rawIntensity;
    }

    // Leave if not found:
    std::string rightnow = now();
    if (!found)
    {
        const float elapsed = GetTimeMillis() - start;
        printf("%s: Checked %d possibilities in %5.1f secs, %3.3f MH/s\n", rightnow.c_str(), checked, elapsed / 1000,
            (checked / 1e6) / (elapsed / 1e3));
        return ret;
    }

    printf("%s: Solution! Checked %d possibilities\n", rightnow.c_str(), checked);

    UniValue tmp(UniValue::VOBJ);
    tmp.pushKV("id", id);
    tmp.pushKV("nonce", HexStr(nonce));
    ret.push_back(tmp);

    return ret;
}

static UniValue RPCSubmitSolution(const UniValue &solution, int &nblocks)
{
    UniValue reply = CallRPC("submitminingsolution", solution);

    const UniValue &error = find_value(reply, "error");

    if (!error.isNull())
    {
        fprintf(stderr, "%s: Block Candidate submission error: %d %s\n", now().c_str(), error["code"].get_int(),
            error["message"].get_str().c_str());
        return reply;
    }

    const UniValue &result = find_value(reply, "result");

    if (result.isNull())
    {
        printf("%s: Unknown submission error, server gave no result\n", now().c_str());
    }
    else
    {
        const UniValue &errValue = find_value(result, "result");

        const UniValue &hashUV = find_value(result, "hash");
        std::string hashStr = hashUV.isNull() ? "" : hashUV.get_str();

        const UniValue &heightUV = find_value(result, "height");
        uint64_t height = heightUV.isNull() ? -1 : heightUV.get_int();


        if (errValue.isStr())
        {
            fprintf(stderr, "%s: Block Candidate %s rejected. Error: %s\n", now().c_str(), hashStr.c_str(),
                result.get_str().c_str());
            // Print some debug info if the block is rejected
            UniValue dbg = solution[0].get_obj();
            fprintf(stderr, "    id: 0x%x  nonce: %s \n", dbg["id"].get_int(), dbg["nonce"].get_str().c_str());
        }
        else
        {
            if (errValue.isNull())
            {
                printf("%s: Block Candidate %u:%s accepted.\n", now().c_str(), (unsigned int)height, hashStr.c_str());
                if (nblocks > 0)
                    nblocks--; // Processed a block
            }
            else
            {
                fprintf(stderr, "%s: Unknown \"submitminingsolution\" Error.\n", now().c_str());
            }
        }
    }

    return reply;
}

static bool FoundNewBlock()
{
    string strPrint;
    UniValue result;

    try
    {
        UniValue params(UniValue::VARR);
        UniValue replyAttempt = CallRPC("getbestblockhash", params);

        // Parse reply
        result = find_value(replyAttempt, "result");
        const UniValue &error = find_value(replyAttempt, "error");

        if (!error.isNull())
        {
            // Error
            int code = error["code"].get_int();
            if (code == RPC_IN_WARMUP)
                throw CConnectionFailed("server in warmup");
            strPrint = "error: " + error.write();
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n" + errMsg.get_str();
            }

            if (strPrint != "")
            {
                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
            }
            MilliSleep(1000);
        }
        else
        {
            if (result.isStr() && !result.isNull())
            {
                // If the bestblockhash has changed then store it, and return true
                string tmpstr;
                tmpstr = result.get_str();
                std::vector<unsigned char> vec = ParseHex(tmpstr);
                std::reverse(vec.begin(), vec.end()); // sent reversed
                {
                    LOCK(cs_blockhash);
                    uint256 hash = uint256(vec);
                    if (hash != bestBlockHash)
                    {
                        bestBlockHash = hash;
                        return true;
                    }
                }
            }
        }
    }
    catch (const CConnectionFailed &c)
    {
        printf("%s: Warning: %s\n", now().c_str(), c.what());
        MilliSleep(1000);
    }

    return false;
}

static bool CheckForNewMiningCandidate()
{
    int coinbasesize = GetArg("-coinbasesize", 0);
    std::string address = GetArg("-address", "");

    string strPrint;
    UniValue result;

    try
    {
        UniValue replyAttempt;
        UniValue params(UniValue::VARR);
        {
            if (coinbasesize > 0)
            {
                params.push_back(UniValue(coinbasesize));
            }
            if (!address.empty())
            {
                if (params.empty())
                {
                    // param[0] must be coinbaseSize:
                    // push null in position 0 to use server default coinbaseSize
                    params.push_back(UniValue());
                }
                // this must be in position 1
                params.push_back(UniValue(address));
                params.push_back(minerName);
            }
            else if (!minerName.empty())
            {
                params.push_back(UniValue());
                params.push_back("");
                params.push_back(minerName);
            }
            replyAttempt = CallRPC("getminingcandidate", params);
        }

        // Parse reply
        result = find_value(replyAttempt, "result");
        const UniValue &error = find_value(replyAttempt, "error");

        if (!error.isNull())
        {
            // Error
            int code = error["code"].get_int();
            if (code == RPC_IN_WARMUP)
                throw CConnectionFailed("server in warmup");
            strPrint = "error: " + error.write();
            if (error.isObject())
            {
                UniValue errCode = find_value(error, "code");
                UniValue errMsg = find_value(error, "message");
                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                if (errMsg.isStr())
                    strPrint += "error message:\n" + errMsg.get_str();
            }

            if (strPrint != "")
            {
                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
            }
            MilliSleep(1000);
        }
        else
        {
            if (!result.isNull() && !result.isStr())
            {
                // save the prev block CheapHash & current difficulty to the global shared
                // variable right away: this will potentially signal to other threads to return
                // early if they are still mining on top of an old block (assumption here is
                // that this block is the latest result from the RPC server, which is true 99.99999%
                // of the time.)
                uint256 headerCommitment;
                uint32_t nBits = 0;
                UniValue id;
                CpuMinerJsonToData(result, headerCommitment, nBits, id);

                {
                    LOCK(cs_commitment);
                    g_headerCommitment = headerCommitment;
                    g_nBits = nBits;
                    g_id = id;
                }
                const BlkInfo blkInfo = {headerCommitment.GetCheapHash(), nBits};
                sharedBlkInfo.store(blkInfo);
                return true;
            }
        }
    }
    catch (const CConnectionFailed &c)
    {
        printf("%s: Warning: %s\n", now().c_str(), c.what());
        MilliSleep(1000);
    }

    // Set the nBits to zero so that the miner threads will pause mining.
    LOCK(cs_commitment);
    g_nBits = 0;

    return false;
}

int CpuMiner(int threadNum)
{
	cl_uint numPlatforms = 0;
	cl_int ret;

	ret = clGetPlatformIDs( 0, nullptr, &numPlatforms );
    if ( ret != CL_SUCCESS )
    {
        printf( "OpenCL: failed on clGetPlatformIDs\n" );
    }

	cl_platform_id *platforms = new cl_platform_id[ numPlatforms ];
	ret = clGetPlatformIDs( numPlatforms, platforms, nullptr );
    if ( ret != CL_SUCCESS )
    {
        printf( "OpenCL: failed on clGetPlatformIDs\n" );
    }

    for ( int platform = 0; platform < numPlatforms; platform++ )
    {
        char buf[128];
	    ret = clGetPlatformInfo( platforms[ platform ], CL_PLATFORM_VENDOR, sizeof(buf), buf, nullptr );

        if ( ret == CL_SUCCESS )
        {
            printf( "OpenCL platform: %s\n", buf );
        }

        bool isNvidia = strstr( buf, "NVIDIA" );

        cl_uint numDevices;
        ret = clGetDeviceIDs( platforms[ platform ], CL_DEVICE_TYPE_GPU, 0, nullptr, &numDevices );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed on clGetDeviceIDs\n" );
        }

        cl_device_id *devices = new cl_device_id[ numDevices ];
        ret = clGetDeviceIDs( platforms[ platform ], CL_DEVICE_TYPE_GPU, numDevices, devices, nullptr );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed on clGetDeviceIDs\n" );
        }

        g_deviceId[ threadNum ] = devices[ threadNum ];

        char ver[128] = { 0 };
		if ( clGetDeviceInfo( g_deviceId[ threadNum ], CL_DRIVER_VERSION, sizeof(ver), ver, nullptr ) == CL_SUCCESS )
        {
            printf( "OpenCL: driver version is \"%s\"\n", ver );
        }

        char gpuCodename[256] = {0};
		if ( clGetDeviceInfo( g_deviceId[ threadNum ], CL_DEVICE_NAME, 256, gpuCodename, nullptr ) == CL_SUCCESS )
        {
            printf( "OpenCL: device name is \"%s\"\n", gpuCodename );
        }

        g_isNvidia[ threadNum ] = isNvidia;
        g_deviceContext[ threadNum ] = clCreateContext( nullptr, 1, &g_deviceId[ threadNum ], nullptr, nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed on clCreateContext for device %i\n", threadNum );
        }

        const cl_command_queue_properties commandQueueProperties = { 0 };
		g_deviceCommandQueue[ threadNum ] = clCreateCommandQueue( g_deviceContext[ threadNum ], g_deviceId[ threadNum ], commandQueueProperties, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed on clCreateCommandQueue for device %i\n", threadNum );
        }

        g_bufferInput[ threadNum ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, 256 * 256, nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate input buffer\n" );
        }
        g_bufferOutput[ threadNum ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, ( 1 + 512 + 512 ) * sizeof(cl_ulong), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate output buffer\n" );
        }
        g_bufferTarget[ threadNum ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, 8 * sizeof(cl_ulong), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate target buffer\n" );
        }

        g_bufferHash[ threadNum ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, g_rawIntensity * 24 * sizeof(cl_uint), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate hash buffer\n" );
        }

        g_bufferExtra[ threadNum ][ secp256k1_hashOut ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, g_rawIntensity * 16 * sizeof(cl_uint), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate hash buffer\n" );
        }

        g_bufferExtra[ threadNum ][ secp256k1_pubkey ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, g_rawIntensity * 24 * sizeof(cl_uint), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate hash buffer\n" );
        }

        g_bufferExtra[ threadNum ][ secp256k1_pubkey2 ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, g_rawIntensity * 24 * sizeof(cl_uint), nullptr, &ret );
        if ( ret != CL_SUCCESS )
        {
            printf( "OpenCL: failed to allocate hash buffer\n" );
        }

        size_t windows = (256 / g_curveBits) + 1;
	    size_t window_size = (1 << (g_curveBits - 1));
	    size_t precomp_size = 64UL * windows * window_size;

		g_bufferExtra[ threadNum ][ secp256k1_pj ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, 128UL * (uint64_t)g_rawIntensity, nullptr, &ret );
		if ( ret != CL_SUCCESS )
		{
			printf( "OpenCL: failed to allocate gej buffer\n" );
		}

		g_bufferExtra[ threadNum ][ secp256k1_precomp ] = clCreateBuffer( g_deviceContext[ threadNum ], CL_MEM_READ_WRITE, precomp_size, nullptr, &ret );
		if ( ret != CL_SUCCESS )
		{
			printf( "OpenCL: failed to allocate precomp buffer\n" );
		}

        printf( "GPU #%i: start fill precompute\n", threadNum );
		for ( size_t i = 0; i < precomp_size; i += 1024 * 1024 )
		{
			void *precomp = &((uint8_t*)g_secp256k1_precompute_20)[ i ];
			if ( i > precomp_size - 1024 * 1024 )
			{
				clEnqueueWriteBuffer( g_deviceCommandQueue[ threadNum ], g_bufferExtra[ threadNum ][ secp256k1_precomp ], CL_TRUE, i, precomp_size - i, precomp, 0, nullptr, nullptr );
			}
			else
			{
				clEnqueueWriteBuffer( g_deviceCommandQueue[ threadNum ], g_bufferExtra[ threadNum ][ secp256k1_precomp ], CL_TRUE, i, 1024 * 1024, precomp, 0, nullptr, nullptr );
			}
		}
        printf( "GPU #%i: finish fill precompute\n", threadNum );

        const char *source = "#include \"secp256k1.cl\"";
        size_t sourceLen = strlen( source );
        g_program[ threadNum ] = clCreateProgramWithSource( g_deviceContext[ threadNum ], 1, &source, &sourceLen, &ret );
        ret = clBuildProgram( g_program[ threadNum ], 1, &g_deviceId[ threadNum ], "-DOPENCL -DNVIDIA -cl-nv-cstd=CL2.0 -nv-m64", nullptr, nullptr );
        if ( ret != CL_SUCCESS )
        {
            size_t len;
            printf( "OpenCL: failed when on clBuildProgram\n" );

            if ( ( ret = clGetProgramBuildInfo( g_program[ threadNum ], g_deviceId[ threadNum ], CL_PROGRAM_BUILD_LOG, 0, nullptr, &len ) ) != CL_SUCCESS )
            {
                printf( "OpenCL: failed on clGetProgramBuildInfo for length of build log output\n" );
            }

            char* buildLog = (char*)malloc( len + 1 );
            buildLog[ 0 ] = '\0';

            if ( ( ret = clGetProgramBuildInfo( g_program[ threadNum ], g_deviceId[ threadNum ], CL_PROGRAM_BUILD_LOG, len, buildLog, NULL ) ) != CL_SUCCESS )
            {
                free( buildLog );
                printf( "OpenCL: failed on clGetProgramBuildInfo for build log\n" );
            }
            printf( buildLog );
            free( buildLog );

            return 0;
        }

        g_kernels[ threadNum ][ kernel_nexapow ] = clCreateKernel( g_program[ threadNum ], "nexapow", &ret );
        g_kernels[ threadNum ][ kernel_nexapow_start ] = clCreateKernel( g_program[ threadNum ], "nexapow_start", &ret );
        g_kernels[ threadNum ][ kernel_secp256k1_64 ] = clCreateKernel( g_program[ threadNum ], "secp256k1_64", &ret );
        g_kernels[ threadNum ][ kernel_sha256_32 ] = clCreateKernel( g_program[ threadNum ], "sha256_32", &ret );
        g_kernels[ threadNum ][ kernel_sha256_40 ] = clCreateKernel( g_program[ threadNum ], "sha256_40", &ret );
        g_kernels[ threadNum ][ kernel_sha256_64 ] = clCreateKernel( g_program[ threadNum ], "sha256_64", &ret );
        g_kernels[ threadNum ][ kernel_checkhash_64 ] = clCreateKernel( g_program[ threadNum ], "checkhash_64", &ret );

        delete []devices;
    }

    // Initialize random number generator lambda. This is per-thread and
    // is thread-safe.  std::rand() is not thread-safe and can result
    // in multiple threads doing redundant proof-of-work.
    std::random_device rd;
    // seed random number generator from system entropy source (implementation defined: usually HW)
    std::default_random_engine e1(rd());
    // returns a uniformly distributed random number in the inclusive range: [0, UINT_MAX]
    std::uniform_int_distribution<uint32_t> uniformGen(0);
    auto randFunc = [&](void) -> uint32_t { return uniformGen(e1); };

    int searchDuration = GetArg("-duration", 30);
    int nblocks = GetArg("-nblocks", -1); //-1 mine forever
    int coinbasesize = GetArg("-coinbasesize", 0);
    std::string address = GetArg("-address", "");

    if (coinbasesize < 0)
    {
        printf("%s: Negative coinbasesize not reasonable/supported.\n", now().c_str());
        return 0;
    }

    UniValue mineresult;
    bool found = false;

    if (0 == nblocks)
    {
        printf("%s: Nothing to do for zero (0) blocks\n", now().c_str());
        return 0;
    }

    while (0 != nblocks)
    {
        UniValue result;
        string strPrint;
        int nRet = 0;
        try
        {
            // Execute and handle connection failures with -rpcwait
            do
            {
                try
                {
                    UniValue replyAttempt;
                    if (found)
                    {
                        // Submit the solution.
                        // Called here so all exceptions are handled properly below.
                        replyAttempt = RPCSubmitSolution(mineresult, nblocks);
                        if (nblocks == 0)
                            return 0; // Done mining exit program
                        found = false; // Mine again

                        result = find_value(replyAttempt, "result");

                        UniValue params(UniValue::VARR);
                        if (coinbasesize > 0)
                        {
                            params.push_back(UniValue(coinbasesize));
                        }
                        if (!address.empty())
                        {
                            if (params.empty())
                            {
                                // param[0] must be coinbaseSize:
                                // push null in position 0 to use server default coinbaseSize
                                params.push_back(UniValue());
                            }
                            // this must be in position 1
                            params.push_back(UniValue(address));
                        }

                        replyAttempt = CallRPC("getminingcandidate", params);
                        result = find_value(replyAttempt, "result");

                        const UniValue &error = find_value(replyAttempt, "error");
                        if (!error.isNull())
                        {
                            // Error
                            int code = error["code"].get_int();
                            if (code == RPC_IN_WARMUP)
                                throw CConnectionFailed("server in warmup");
                            strPrint = "error: " + error.write();
                            nRet = abs(code);
                            if (error.isObject())
                            {
                                UniValue errCode = find_value(error, "code");
                                UniValue errMsg = find_value(error, "message");
                                strPrint = errCode.isNull() ? "" : "error code: " + errCode.getValStr() + "\n";

                                if (errMsg.isStr())
                                    strPrint += "error message:\n" + errMsg.get_str();
                            }
                            printf("%s: ERROR: %s\n", now().c_str(), strPrint.c_str());
                            throw;
                        }
                        else
                        {
                            // Result
                            if (result.isNull())
                                strPrint = "";
                            else if (result.isStr())
                                strPrint = result.get_str();
                        }

                        if (strPrint != "")
                        {
                            if (nRet != 0)
                            {
                                fprintf(stderr, "%s: %s\n", now().c_str(), strPrint.c_str());
                                return 0;
                            }
                            if (result.isStr())
                            {
                                // This can happen just after submitting a block and the old block template
                                // becomes stale
                                printf("%s: Not mining because: %s\n", now().c_str(), result.get_str().c_str());
                                return 0;
                            }
                        }
                        else if (result.isNull())
                        {
                            printf("%s: No result after submission\n", now().c_str());
                            MilliSleep(1000);
                        }
                        else
                        {
                            // Update the new best block hash.
                            FoundNewBlock();

                            // Block submission was successfull so retrieve the new mining candidate
                            printf("%s: Getting new Candidate after successful block submission\n", now().c_str());
                            if (!CheckForNewMiningCandidate())
                                return 0;
                        }
                    }

                    // Connection succeeded, no need to retry.
                    break;
                }
                catch (const CConnectionFailed &c)
                {
                    printf("%s: Warning: %s\n", now().c_str(), c.what());
                    MilliSleep(1000);
                }
            } while (true);
        }
        catch (const boost::thread_interrupted &)
        {
            throw;
        }
        catch (const std::exception &e)
        {
            strPrint = string("error: ") + e.what();
            nRet = EXIT_FAILURE;
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
            throw;
        }


        // Actually do some mining
        found = false;
        mineresult = CpuMineBlock(searchDuration, found, randFunc, threadNum);
        if (!found)
        {
            mineresult.setNull();
        }
        // The result is sent to nexad above when the loop gets to it.
        // See:   RPCSubmitSolution(mineresult,nblocks);
        // This is so RPC Exceptions are handled in one place.
    }

    delete []platforms;

    return 0;
}


int main(int argc, char *argv[])
{
    size_t windows = (256 / g_curveBits) + 1;
	size_t window_size = (1 << (g_curveBits - 1));
	size_t precomp_size = 64UL * windows * window_size;

	g_secp256k1_gej_temp = (void*)malloc( 128 * window_size );
	g_secp256k1_z_ratio = (void*)malloc( 4 * 10 * window_size );
	g_secp256k1_precompute_20 = (void*)malloc( precomp_size );
					
    printf( "CPU: start precompute\n" );
	secp256k1_ecmult_big_create( g_curveBits, (secp256k1_gej*)g_secp256k1_gej_temp, (uint32_t*)g_secp256k1_z_ratio, (secp256k1_ge_storage*)g_secp256k1_precompute_20 );
    printf( "CPU: finish precompute\n" );

    int ret = EXIT_FAILURE;

    Secp256k1Init secp;
    SetupEnvironment();
    if (!SetupNetworking())
    {
        fprintf(stderr, "Error: Initializing networking failed\n");
        exit(1);
    }

    try
    {
        std::string appname("nexa-miner");
        std::string usage = "\n" + _("Usage:") + "\n" + "  " + appname + " [options] " + "\n";
        ret = AppInitRPC(usage, NexaMinerArgs(), argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception &e)
    {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    }
    catch (...)
    {
        PrintExceptionContinue(nullptr, "AppInitRPC()");
        return EXIT_FAILURE;
    }
    SelectParams(ChainNameFromCommandLine());

    minerName = GetArg("-name", "");

    // Launch miner threads
    int nThreads = GetArg("-cpus", 1);
    if (nThreads > 256)
    {
        nThreads = 256;
        printf("%s: Number of threads reduced to the maximum allowed value: %d.\n", now().c_str(), nThreads);
    }
    std::vector<std::thread> minerThreads;
    printf("%s: Running %d threads.\n", now().c_str(), nThreads);
    minerThreads.resize(nThreads);
    for (int i = 0; i < nThreads; i++)
        minerThreads[i] = std::thread(MinerThread, i);

    deterministicStartCount = GetBoolArg("-deterministic", false);

    // Start loop which checks whether we have a new mining candidate
    uint64_t nStartTime = 0;
    do
    {
        try
        {
            // only check for new candidates every 2 seconds, or if the bestblockhash has changed.
            if ((GetTimeMillis() - nStartTime > 2000) || FoundNewBlock())
            {
                nStartTime = GetTimeMillis();
                CheckForNewMiningCandidate();
            }
            MilliSleep(100);
        }
        catch (const std::exception &e)
        {
            PrintExceptionContinue(&e, "CommandLineRPC()");
            MilliSleep(1000);
        }
        catch (...)
        {
            PrintExceptionContinue(nullptr, "CommandLineRPC()");
            MilliSleep(1000);
        }
    } while (true);

    return ret;
}
