// Copyright (c) 2018-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "forks.h"

#include "unlimited.h"

extern std::atomic<bool> forceTemplateRecalc;

/** Fork1 time MTP >= 12:00:00 PM, March 31st 2025, GMT */
const uint64_t FORK1_ACTIVATION_TIME = 1743422400;

// Fork1 on March 31st 2025
bool IsFork1Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }
    // Fork1 enables in the block AFTER the activation.  This gives us time to clean out the txpool.
    return pindexTip->pprev->GetMedianTimePast() >= (int64_t)FORK1_ACTIVATION_TIME;
}

// Fork1 on March 31st 2025
bool IsFork1Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return !IsFork1Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)FORK1_ACTIVATION_TIME);
}

bool IsFork2Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }

    bool fActivated = false;
    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() > 2)
    {
        fActivated = true;
    }
    if (pindexTip->pprev->GetMedianTimePast() >= (int64_t)nMiningForkTime)
    {
        fActivated = true;
    }

    return fActivated;
}

bool IsFork2Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }

    bool fPending = false;
    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() >= 2)
    {
        fPending = true;
    }
    if (!IsFork2Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)nMiningForkTime))
    {
        fPending = true;
    }

    if (fPending)
    {
        // Processes to run only once when fork is pending.
        static bool fRunOnce = true;
        if (fRunOnce)
        {
            // Clear out mining candidates and force a new one to be created for the next block
            // which will be the fork block.
            {
                LOCK(csMiningCandidates);
                miningCandidatesMap.clear();
                forceTemplateRecalc.store(true);
            }

            // Get any subblocks that may have been mined already prior to our own fork activation.
            // We must do this because the first subblock header may already have arrived however because
            // tailstorm was not enabled it would have been rejected as not having enough POW. So we need
            // to re-request any subblocks here so they properly ends up the subblock dag.
            {
                LOCK(cs_vNodes);
                for (CNode *pnode : vNodes)
                {
                    std::set<uint256> setDagToSend;
                    pnode->PushMessage(NetMsgType::GET_DAG, setDagToSend);
                }
            }
            fRunOnce = false;
        }
    }

    return fPending;
}
