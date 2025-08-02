// Copyright (c) 2025 The Bitcoin Unlimited developers

#ifndef NEXA_TAILSTORM_H
#define NEXA_TAILSTORM_H

#include "consensus/validation.h"
#include "primitives/block.h"
#include "sync.h"
#include "uint256.h"
#include "validation/dag.h"

#include <cstdint>
#include <utility>
#include <vector>

extern std::atomic<bool> fTailstormEnabled;

class CBlockIndex;

/** current version of miner data held in the block header */
static const uint8_t DEFAULT_MINER_DATA_VERSION = 1;

/** Prune subblocks from the dag if they in this block */
void PruneSubblocks(ConstCBlockRef pblock);

/** Is this subblock a summary block */
bool IsSummaryBlock(ConstCBlockRef pblock);
bool IsSummaryBlock(const CBlock &block);

/** Store this valid subblock for use in the DAG */
void AcceptSubblock(ConstCBlockRef pblock);

std::vector<uint8_t> GenerateMinerData(uint64_t heightPrevBlock,
    uint256 hashPrevBlock,
    uint32_t tailstorm_k,
    std::set<CTreeNodeRef> &setBestDag);

#endif
