// Copyright (c) 2020-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"

#include "consensus/consensus.h"
#include "daa.h"
#include "requestManager.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "validation/validation.h"

extern bool IsInitialBlockDownload();
extern CCriticalSection cs_main;

class CValidationState;

CBlockIndex *LookupBlockIndex(const uint256 &hash);
bool IsSummaryBlock(const CBlock &block);

// Find the hash of the tip of the dag which has the best dag height
static uint256 FindDagTip(std::set<CTreeNodeRef> &bestDag)
{
    uint256 activetip;
    unsigned int bestHeight = 0;
    for (auto &node : bestDag)
    {
        if (node->IsTip())
        {
            if (node->dagHeight > bestHeight)
            {
                activetip = node->hash;
                bestHeight = node->dagHeight;
            }
            else if (node->dagHeight == bestHeight)
            {
                if (node->hash < activetip)
                {
                    activetip = node->hash;
                }
            }
        }
    }
    return activetip;
}

// Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &setBestDag)
{
    uint256 activetip = FindDagTip(setBestDag);
    if (activetip.IsNull())
    {
        return chainActive.Tip()->GetBlockHash();
    }

    return activetip;
}

// Tailstorm Tree
bool CTailstormTree::Insert(CTreeNodeRef newNode, bool *fAllowRecursion)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (!newNode->subblock)
        return false;

    // Add to the tree
    auto res = dag.emplace(newNode->hash, newNode);
    if (res.second)
    {
        bool fDoubleSpent = false;
        CValidationState state;
        bool fOK = true;
        {
            ConstCBlockRef pblock = newNode->subblock;
            const CChainParams &chainparams = Params();
            bool fJustCheck = false;
            bool fParallel = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(pblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

            // Try connecting the block and updating the coins cache.  If successful then we can remove
            // the transactions from the mempool.
            CCoinsViewCache upperview(view);
            if (!ConnectBlockCanonicalOrdering(pblock, state, pindexSummaryRoot, upperview, chainparams, fJustCheck,
                    fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages, accumulatedAuthorities,
                    &mapDagTxns))
            {
                fOK = false;

                int nDos = 0;
                if (state.IsInvalid(nDos))
                {
                    // Check if this subblock is double spending anything in the dag
                    // and if so then fork a new dag and use this subblock as it's
                    // tip.
                    if (state.GetRejectCode() == REJECT_CONFLICT)
                    {
                        fDoubleSpent = true;
                    }
                }
            }
            else
            {
                // Stop txadmission, and flush the commitQ, before we flush coin state and remove txn conflicts
                TxAdmissionPause txlock;

                // Flush coin state after subblock is validated without error
                bool result = upperview.Flush();
                assert(result);

                std::list<CTransactionRef> txConflicted;
                // mempool.removeForBlock(pblock->vtx, pblock->height, txConflicted, true);
                // Process orphan pool for transactions in block but do deferr it to be done
                // in another thread.
                // LOCK(orphanpool.cs_blockprocessing);
                // orphanpool.vPostBlockProcessing.push_back(pblock);

                // Remove conflicting txns
                // TODO: need to verify how this is affecting the wallet if at all?
                {
                    WRITELOCK(mempool.cs_txmempool);
                    for (const auto &tx : pblock->vtx)
                    {
                        mempool._removeConflicts(*tx, txConflicted);
                    }
                }

                cvCommitQ.notify_all();
            }
        }

        if (fDoubleSpent)
        {
            LOG(DAG, "%s: subbblock %s is a double spend block: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());

            // Remove the invalid treenode from the dag before continuing.
            dag.erase(newNode->hash);

            // fork another tree if if truly have a double spend subblock.

            // Find the subblock that conflicts with our new subblock we're trying to connect by doing the following:
            // 1) Create a map of our subblock by input and transaction
            // 2) Use this map as we cycle back through the last subblocks going from highest sequence_id to lowest.
            // 3) If you do find a competing block then fork the entire dag (minus the ds block we're replacing and
            // any of its descendants) and put the competing subblock at the tip.
            // 4) Then populate the coinscache for the newly forked dag.

            // If you don't find any competing blocks (meaning this wasn't actually a ds block but some kind of fake
            // block) then just do nothing and drop the subblock.

            // Create the outpoint map
            std::map<COutPoint, CTransactionRef> mapOutpoints;
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase())
                    continue;

                for (size_t j = 0; j < ptx->vin.size(); j++)
                {
                    mapOutpoints[ptx->vin[j].prevout] = ptx;
                }

                // TODO: for efficiency we could populate a map here which we could merge later.
                // mapDagTxns.emplace(ptx->GetId(), ptx);
            }

            // Cycle through the dag from highest sequence id to lowest looking for a conflicting subblock.
            ConstCBlockRef pConflictingSubblock = nullptr;
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(dag.begin(), dag.end());
            std::sort(vSortedDag.begin(), vSortedDag.end(),
                [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
            for (auto it = vSortedDag.rbegin(); it != vSortedDag.rend(); it++)
            {
                for (CTransactionRef ptx : it->second->subblock->vtx)
                {
                    if (ptx->IsCoinBase())
                        continue;

                    for (size_t j = 0; j < ptx->vin.size(); j++)
                    {
                        if (mapOutpoints.count(ptx->vin[j].prevout))
                        {
                            pConflictingSubblock = it->second->subblock;
                            break;
                        }
                    }
                    if (pConflictingSubblock)
                        break;
                }
                if (pConflictingSubblock)
                    break;
            }

            // If we find a conflicting subblock then fork the dag otherwise do nothing.
            if (pConflictingSubblock)
            {
                LOG(DAG, "%s: Found Conflicting subblock %s", __func__, pConflictingSubblock->GetHash().ToString());

                if (fAllowRecursion != nullptr && *fAllowRecursion == false)
                {
                    LOG(DAG, "%s: Returning false because no recursion allowed", __func__);
                    return false;
                }

                // Create the new tree and add it to the grove.
                //
                // This new forked tree is created by starting at the root of the current tree and adding all
                // decendant subblocks with the exception of the the double spent subblock, which is swapped
                // with the new conflicting subblock.
                //
                // Once the new tree is forked, any new subblocks received have to be checked against both trees
                // because of the possibiilty that there might have been multiple tips at the fork height which
                // could then potentially be extended by either fork.
                //
                // TODO: need a discussion about an easy double spend attack which is possible by double spending
                // a subblock on an old branch of the tree.  There are only two solutions to this problem. One is
                // to introduce some kind of finalization into tailstorm, where we would only allow old subblocks
                // that are perhaps less than 10 subblocks deep.  The other solution which is perhaps better but
                // requires more work to implement is to have all tree tips connected to the chain by allowing multiple
                // previous subblock hashes in the header which would link all tips and thus prevent the injection of
                // old or very old sublocks into the chain.
                std::shared_ptr<CTailstormTree> doubleSpendTree(std::make_shared<CTailstormTree>(CTailstormTree()));
                doubleSpendTree->view = new CCoinsViewCache(_pcoinsTip);
                doubleSpendTree->view->SetBestBlock(*(pindexSummaryRoot->phashBlock));
                doubleSpendTree->pindexSummaryRoot = pindexSummaryRoot;

                // Connect subblocks from lowest sequence id to highest to ensure txn chain dependencies are handled.
                LOG(DAG, "%s: Begin inserting into double spend tree", __func__);
                for (auto it = vSortedDag.begin(); it != vSortedDag.end(); it++)
                {
                    LOG(DAG, "%s: Connecting %s into new double spend tree with sequence id: %d", __func__,
                        it->second->hash.ToString(), it->second->nSequenceId);
                    // When doing an insert for a double spend tree and it fails we want to prevent
                    // creating a second double spend tree. While unlikely it's a good idea to prevent
                    // what could be some sort of infinite recursion.
                    bool fAllow = false;

                    ConstCBlockRef subblock = nullptr;
                    if (it->first != pConflictingSubblock->GetHash())
                    {
                        if (doubleSpendTree->Insert(it->second, &fAllow))
                        {
                            subblock = it->second->subblock;
                        }
                    }
                    else
                    {
                        if (doubleSpendTree->Insert(newNode, &fAllow))
                        {
                            subblock = newNode->subblock;
                        }
                    }

                    // Update the map of transactions if the insert was successful.
                    if (subblock)
                    {
                        LOG(DAG, "%s: Inserted %s into new double spend tree", __func__,
                            subblock->GetHash().ToString());

                        for (CTransactionRef ptx : subblock->vtx)
                        {
                            if (ptx->IsCoinBase())
                                continue;

                            doubleSpendTree->mapDagTxns.emplace(ptx->GetId(), ptx);
                            LOG(DAG, "%s: add txn : %s to mapDagTxns", __func__, ptx->GetId().ToString());
                        }
                    }
                }
                LOG(DAG, "%s: End inserting into double spend tree", __func__);

                // Insert the new double spend tree into the correct grove and activate the best tree
                CTailstormGroveRef grove = nullptr;
                if (tailstormForest.GetGrove(newNode->subblock->hashPrevBlock, grove))
                {
                    grove->setValidTrees.insert(doubleSpendTree);
                    grove->ActivateBestTree();
                    LOG(DAG, "%s: Inserted new double spend tree of size %ld into grove", __func__,
                        doubleSpendTree->dag.size());
                }
                return true;
            }
            else
            {
                LOG(DAG, "%s: subbblock %s is invalid and could not be connected to the dag: %s", __func__,
                    newNode->hash.ToString(), state.GetLogString());
                return false;
            }
        }
        if (!fOK)
        {
            dag.erase(newNode->hash);
            LOG(DAG, "%s: subbblock %s failed to validate: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());

            return false;
        }

        // Update the sequence id
        newNode->nSequenceId = dag.size();

        // Update the map of all current dag transactions
        // TODO: you could prepare this map in the upper loop and then merge it
        // if the subblock passes validation.
        for (CTransactionRef ptx : newNode->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapDagTxns.emplace(ptx->GetId(), ptx);
        }

        // Set the tree pointer for the grove to the best tree in the grove
        CTailstormGroveRef grove = nullptr;
        if (tailstormForest.GetGrove(*(pindexSummaryRoot->phashBlock), grove))
        {
            grove->ActivateBestTree();
            LOG(DAG, "%s: Activating best tree", __func__);
        }

        return true;
    }

    return true; // must return true because we already have it and don't want it deleted from the grove
}

// Tailstorm Grove
bool CTailstormGrove::InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache)
{
    AssertLockHeld(tailstormForest.cs_forest);

    assert(coinsCache);
    assert(newNode);

    if (!newNode->subblock)
        return false;

    const uint256 &prevSummaryHash = newNode->subblock->hashPrevBlock;
    roothash = prevSummaryHash;

    // In case we attempted to initialize before and failed
    if (tree->view)
    {
        delete tree->view;
        tree->view = nullptr;
    }

    tree->_pcoinsTip = coinsCache;
    tree->view = new CCoinsViewCache(coinsCache);
    tree->view->SetBestBlock(prevSummaryHash);
    tree->pindexSummaryRoot = LookupBlockIndex(prevSummaryHash);
    assert(tree->pindexSummaryRoot);

    return tree->Insert(newNode);
}

void CTailstormGrove::Clear()
{
    AssertLockHeld(tailstormForest.cs_forest);

    // delete all of the nodes in this grove. mapGroveNodes is
    // a subset of mapAllNodes which we can iterate over to efficiently remove
    // the nodes from mapAllNodes
    for (auto &iter : mapGroveNodes)
    {
        tailstormForest.mapAllNodes.erase(iter.first);
        tailstormForest.mapAllGroves.erase(iter.first);
        tailstormForest.mapAllGrovesByPrev.erase(iter.first);
    }

    mapGroveNodes.clear();
}

bool CTailstormGrove::InsertIntoTree(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (!newNode->subblock)
        return false;

    // Check all trees and make sure we don't already have this item. It could be in
    // a double spend tree and if so we don't want to process it again otherwise might
    // end up forking another duplicate double spend tree.
    for (auto it : setValidTrees)
    {
        if (it->dag.count(newNode->hash))
        {
            LOG(DAG, "Not inserting new node since treenode already exists");
            return false;
        }
    }

    // Add the very first tree items.  These are subblocks with dagHeight 1.  The first time through
    // we initialize the tree.  If there is a second subblock at dagHeight 1 then we just do a simple insert.
    uint256 prevHash = newNode->subblock->hashPrevBlock;
    if (tree->dag.empty() || (!prevHash.IsNull() && prevHash == roothash))
    {
        newNode->dagHeight = 1;
        LOG(DAG, "%s(): updated dagHeight to %ld for %s", __func__, newNode->dagHeight, newNode->hash.ToString());

        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            // The first subblock we receive the roothash will be null so we create
            // the tree. However we may still receive a second subblocks with dag height of "1"
            // (forming a tree with two roots) so on the second pass we just add the new subblock
            // to the tree.
            if (!prevHash.IsNull() && prevHash != roothash)
            {
                if (!InitializeTree(newNode, _pcoinsTip))
                {
                    mapGroveNodes.erase(newNode->hash);
                    return false;
                }
            }
            else
            {
                if (!tree->Insert(newNode))
                {
                    mapGroveNodes.erase(newNode->hash);
                    return false;
                }
            }

            // Notify the dagviewer
            ConstCBlockRef pblock = newNode->subblock;
            const CBlockHeader header = pblock->GetBlockHeader();
            const uint256 &hashprev = header.hashPrevBlock;
            uint32_t nSequenceId = newNode->nSequenceId;
            uiInterface.NotifyBlockTipDag(false, tailstormForest.GetDagHeight(hashprev) + 1, nSequenceId, header, true);
        }
    }
    else // Insert all other tree items
    {
        // Check that the prevhash exists in grove nodes
        std::map<uint256, CTreeNodeRef>::iterator prev_iter = mapGroveNodes.find(prevHash);
        if (prev_iter == mapGroveNodes.end())
        {
            LOG(DAG, "%s(): ERROR, subblock %s previous subblock %s is missing from the grove", __func__,
                newNode->hash.GetHex().c_str(), prevHash.GetHex());
            return false;
        }

        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            // Did we add at least one node to a tree
            bool fAddedOne = false;

            // A subblock could be valid in more than one tree so check each tree
            // in the grove and try to see if the subblock can be added.
            //
            // It could also be valid in one tree but not the other so we have to
            // be careful of that as well.
            for (auto _tree : setValidTrees)
            {
                // check that we have the treenode of the prevHash
                CTreeNodeRef prevNode = nullptr;
                {
                    // Then find it in our tree
                    auto iter_tree = _tree->dag.find(prevHash);
                    if (iter_tree == _tree->dag.end())
                    {
                        continue;
                    }
                    else
                    {
                        prevNode = iter_tree->second;
                        LOG(DAG, "%s(): Found prevhash in dag %s for %s", __func__, prevHash.ToString(),
                            iter_tree->second->hash.ToString());
                    }
                }

                // add ancestor information regardless of being added to the tree
                if (prevNode != nullptr)
                {
                    newNode->AddAncestor(prevNode);
                    newNode->dagHeight = prevNode->dagHeight + 1;
                    prevNode->AddDescendant(newNode);
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld for %s", __func__, newNode->dagHeight,
                        _tree->dag.size(), newNode->hash.ToString());
                }
                else
                {
                    newNode->dagHeight = 1;
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld  for %s", __func__, newNode->dagHeight,
                        _tree->dag.size(), newNode->hash.ToString());
                }

                // Insert new node into tree
                if (_tree->Insert(newNode))
                {
                    fAddedOne = true;
                    LOG(DAG, "%s(): completed insert into tree dagsize %ld for %s", __func__, _tree->dag.size(),
                        newNode->hash.ToString());
                }
            }

            if (!fAddedOne)
            {
                mapGroveNodes.erase(newNode->hash);
                tailstormForest.mapNodesUnlinked.emplace(newNode->hash, newNode);
                LOG(DAG, "%s(): adding orphan to unused nodes", __func__);

                return false;
            }


            // Notify the dagviewer
            ConstCBlockRef pblock = newNode->subblock;
            const CBlockHeader header = pblock->GetBlockHeader();
            const uint256 &hashprev = header.hashPrevBlock;
            uint32_t nSequenceId = newNode->nSequenceId;
            uiInterface.NotifyBlockTipDag(false, tailstormForest.GetDagHeight(hashprev) + 1, nSequenceId, header, true);
        }
    }

    return true;
}

bool CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    return InsertIntoTree(newNode);
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (tree->dag.empty())
    {
        return false;
    }

    for (auto &node : tree->dag)
    {
        // If the sequence id is too high then don't include it
        if (node.second->nSequenceId > Params().GetConsensus().tailstorm_k - 1)
        {
            LOG(DAG, "%s(): sequence id %d is too high for %s", __func__, node.second->nSequenceId,
                node.second->hash.ToString());
            continue;
        }

        dag.insert(node.second);
    }
    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256 &tiphash)
{
    AssertLockHeld(tailstormForest.cs_forest);

    std::set<CTreeNodeRef> bestDag;
    GetBestDag(bestDag);
    tiphash = FindDagTip(bestDag);
    return true;
}

void CTailstormGrove::ActivateBestTree()
{
    AssertLockHeld(tailstormForest.cs_forest);

    for (std::shared_ptr<CTailstormTree> treeitem : setValidTrees)
    {
        if (treeitem->dag.size() > tree->dag.size())
        {
            tree = treeitem;
            LOG(DAG, "%s: Active tree tip is %s", __func__,
                tailstormForest.GetDagTipHash(*(tree->pindexSummaryRoot->phashBlock)).ToString());
        }
    }
}

// Tailstorm Forest
void CTailstormForest::Clear()
{
    LOCK(cs_forest);
    mapAllGrovesByPrev.clear();
    mapAllGroves.clear();
    mapAllNodes.clear();
    mapNodesUnlinked.clear();
    mapSummaryBlocksUnlinked.clear();
}

void CTailstormForest::ClearGrove(const uint256 &hash)
{
    LOCK(cs_forest);
    auto iter = mapAllGrovesByPrev.find(hash);
    if (iter != mapAllGrovesByPrev.end())
    {
        if (iter->second != nullptr)
        {
            iter->second->Clear();
            iter->second = nullptr;
        }
        mapAllGrovesByPrev.erase(iter);
    }

    auto iter2 = mapAllGroves.find(hash);
    if (iter2 != mapAllGroves.end())
    {
        if (iter2->second != nullptr)
        {
            iter2->second->Clear();
            iter2->second = nullptr;
        }
        mapAllGroves.erase(iter2);
    }

    mapAllNodes.erase(hash);
}

void CTailstormForest::ClearByHeight(const uint32_t nPruneHeight)
{
    AssertLockHeld(tailstormForest.cs_forest);

    auto iter = mapAllNodes.begin();
    while (iter != mapAllNodes.end())
    {
        if (iter->second->subblock && (iter->second->subblock->height <= nPruneHeight))
        {
            const uint256 &hash = iter->first;
            mapNodesUnlinked.erase(hash);
            mapAllGroves.erase(hash);
            mapAllGrovesByPrev.erase(hash);
            iter = mapAllNodes.erase(iter);
            LOGA("pruning subblock %s\n", hash.ToString());
        }
        else
        {
            iter++;
        }
    }
}

size_t CTailstormForest::Size()
{
    LOCK(cs_forest);
    return mapAllNodes.size();
}


bool CTailstormForest::Insert(ConstCBlockRef subblock, CTailstormGroveRef &grove)
{
    AssertLockNotHeld(cs_forest);

    if (!subblock)
        return false;

    LOCK(cs_forest);
    return _Insert(subblock, grove);
}

bool CTailstormForest::_Insert(ConstCBlockRef subblock, CTailstormGroveRef &grove)
{
    AssertLockHeld(cs_forest);

    if (!subblock)
        return false;

    // Create new node
    CTreeNodeRef newNode = MakeTreeNodeRef(subblock);

    // emplace the new node into the map
    if (!mapAllNodes.emplace(newNode->hash, newNode).second)
    {
        // There already exists a node for this subblock
        // We don't want to do anything here because this could be an orphan getting connected
        // which has an entry in mapAllNodes but not yet in mapAllGroves.
    }

    // Insert elements into a new grove or and already existing grove.
    auto mi = mapAllGroves.find(subblock->hashPrevBlock);
    if (mi != mapAllGroves.end())
    {
        // Make sure the height of this subblock equals the prev subblock height.
        for (auto it : mi->second->setValidTrees)
        {
            // find the tree that has a subblock which it connects to.
            if (it->dag.count(subblock->hashPrevBlock))
            {
                if (subblock->height != it->dag[subblock->hashPrevBlock]->subblock->height)
                {
                    LOG(DAG, "%s(): subblock height does not match previous subblock height %s", __func__,
                        subblock->GetHash().ToString(), subblock->hashPrevBlock.ToString());
                    return false;
                }
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(it->pindexSummaryRoot, &(*subblock), Params().GetConsensus());
            auto expectedChainWork =
                ArithToUint256(it->pindexSummaryRoot->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                return false;
            }
        }


        // Insert subblock into already existing grove
        LOG(DAG, "%s(): trying to add subblock to already existing grove %s", __func__, subblock->GetHash().ToString());
        if (mi->second->Insert(newNode))
        {
            mapAllGroves.emplace(subblock->GetHash(), mi->second);
            mapAllGrovesByPrev.emplace(subblock->hashPrevBlock, mi->second);
            grove = mi->second;

            LOG(DAG, "%s(): added subblock %s to existing grove %s with subblock dagHeight %d", __func__,
                subblock->GetHash().ToString(), subblock->hashPrevBlock.ToString(), newNode->dagHeight);
            return true;
        }
        else
        {
            LOG(DAG, "%s(): FAILED to add subblock %s to existing grove %s", __func__, subblock->GetHash().ToString(),
                subblock->hashPrevBlock.ToString());
            return false;
        }
    }
    else
    {
        // At this point we need to know if this block connects to a past
        // Summary Block or if it really is an orphan.
        auto pindex = LookupBlockIndex(subblock->hashPrevBlock);
        if (pindex && pindex->IsValid(BLOCK_VALID_TRANSACTIONS))
        {
            // Make sure the height of this subblock is 1 more that the previous summary block
            if (subblock->height != pindex->height() + 1)
            {
                LOG(DAG, "%s: invalid height - could not add subblock to grove", __func__);
                return false;
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(pindex, &(*subblock), Params().GetConsensus());
            auto expectedChainWork = ArithToUint256(pindex->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                return false;
            }
            // Add new grove and insert subblock
            auto mi_byprev = mapAllGrovesByPrev.find(subblock->hashPrevBlock);
            if (mi_byprev != mapAllGrovesByPrev.end())
            {
                // if it already exists then don't add again.
                auto iter = mapAllGroves.find(subblock->GetHash());
                if (iter != mapAllGroves.end())
                {
                    LOG(DAG, "%s: subblock already exist in grove so not adding again", __func__);
                    return true;
                }

                LOG(DAG, "%s(): added subblock to already existing grove %s with a prev summary  %s", __func__,
                    subblock->GetHash().ToString().c_str(), subblock->hashPrevBlock.GetHex());

                mapAllGroves.emplace(subblock->GetHash(), mi_byprev->second);
                mapAllGrovesByPrev.emplace(subblock->hashPrevBlock, mi_byprev->second);

                grove = mi_byprev->second;
                return grove->Insert(newNode);
            }
            else
            {
                auto res =
                    mapAllGroves.emplace(subblock->GetHash(), MakeTailstormGroveRef(CTailstormGrove(_pcoinsTip)));
                if (res.second)
                {
                    mapAllGrovesByPrev.emplace(subblock->hashPrevBlock, res.first->second);
                    LOG(DAG, "%s(): added subblock %s to new Grove with prev summary is %s", __func__,
                        subblock->GetHash().GetHex(), subblock->hashPrevBlock.GetHex());

                    grove = res.first->second;
                    return grove->Insert(newNode);
                }
                else
                {
                    LOG(DAG, "%s: failed to add new grove", __func__);
                    return false;
                }
            }
        }
        else
        {
            // It must be an orphan
            mapNodesUnlinked.emplace(subblock->GetHash(), newNode);

            LOG(DAG, "%s():added subblock %s to nodes unlinked %s", __func__, subblock->GetHash().GetHex(),
                subblock->hashPrevBlock.GetHex());
            return false;
        }
    }
}

void CTailstormForest::AddSummaryBlockOrphan(ConstCBlockRef pblock)
{
    LOCK(cs_forest);
    mapSummaryBlocksUnlinked.emplace(pblock->GetHash(), pblock);
}

std::set<uint256> CTailstormForest::ProcessOrphans()
{
    AssertLockHeld(cs_forest);

    std::set<uint256> setLinked;
    for (auto iter = mapNodesUnlinked.begin(); iter != mapNodesUnlinked.end();)
    {
        assert(iter->second->subblock);

        const uint256 &prevhash = iter->second->subblock->hashPrevBlock;
        auto pindex = LookupBlockIndex(prevhash);
        if ((pindex && pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) || mapAllGroves.count(prevhash))
        {
            LOG(DAG, "%s(): process orphans - found orphan %s connecting to prev block %s", __func__,
                iter->second->hash.ToString(), prevhash.ToString());
            CTailstormGroveRef grove = nullptr;
            if (_Insert(iter->second->subblock, grove))
            {
                LOG(DAG, "%s(): Insert of orphan succeeded", __func__);
                setLinked.insert(iter->second->subblock->GetHash());

                // The subblock was added to a grove and tree so update
                // the global maps.
                if (grove != nullptr)
                {
                    mapAllGroves.emplace(iter->second->subblock->GetHash(), grove);
                    mapAllGrovesByPrev.emplace(iter->second->subblock->hashPrevBlock, grove);
                }
                else
                    LOG(DAG, "%s(): WARNING: grove was nullptr", __func__);

                mapNodesUnlinked.erase(iter);
                iter = mapNodesUnlinked.begin();
                continue;
            }
            else
            {
                LOG(DAG, "%s(): unlinked insert failed for %s size %ld", __func__, iter->second->hash.ToString(),
                    mapNodesUnlinked.size());
            }
        }
        ++iter;
    }

    // Process any summary block orphans that has all subblocks present and valid in the dag.
    // NOTE: we don't add the summary block to setLinked because block processing doesn't
    // finish in this thread so we can't be sure it's linked.  It will instead get announced
    // once the block successfully connects to the blockchain.
    for (auto iter2 = mapSummaryBlocksUnlinked.begin(); iter2 != mapSummaryBlocksUnlinked.end();)
    {
        const ConstCBlockRef pblock = iter2->second;
        const uint256 &prevhash = pblock->hashPrevBlock;
        {
            // Get all mining hashes from the best dag that exists on top of
            // the prevhash of this Summary Block.  Then Check if all
            // the subblock minining hashes in the minerData of this block
            // are present in the best dag.
            std::set<CTreeNodeRef> dag;
            tailstormForest.GetBestDagFor(pblock->GetBlockHeader().hashPrevBlock, dag);
            LOG(DAG, "%s(): try to process summary orphan - dag size is %ld", __func__, dag.size());
            std::set<uint256> setMiningHashes;
            for (auto &treenode : dag)
            {
                assert(treenode->subblock);

                const auto &miningHeaderCommitment = treenode->subblock->GetMiningHeaderCommitment();
                const auto &nonce = treenode->subblock->GetBlockHeader().nonce;
                setMiningHashes.insert(GetMiningHash(miningHeaderCommitment, nonce));
            }

            // Check to make sure all subblocks were received before connecting the Summary Block
            auto subblockProofs = ParseMinerData(pblock->minerData);
            bool fHaveSubblocks = true;
            for (const auto &pair : subblockProofs)
            {
                const auto &miningHeaderCommitment = pair.first;
                const auto &nonce = pair.second;
                uint256 mininghash = GetMiningHash(miningHeaderCommitment, nonce);

                if (!setMiningHashes.count(mininghash))
                {
                    fHaveSubblocks = false;
                    break;
                }
            }

            LOG(DAG, "%s(): Process Summary block orphans - found summary block %s", __func__,
                iter2->second->GetHash().ToString());
            LOG(DAG, "%s():  connecting summary block to prev block  %s", __func__, prevhash.ToString());
            if (!fHaveSubblocks)
            {
                LOG(DAG, "%s():  FAILED - do not have all subblocks: %ld", __func__, dag.size());
                for (auto &treenode : dag)
                {
                    assert(treenode->subblock);
                    LOG(DAG, "%s(): subblocks in failed dag: %s", __func__,
                        treenode->subblock->GetBlockHeader().GetHash().ToString().c_str());
                }
            }

            // All subblocks are present that are needed to validate the summary block
            // so now we're able to successfully connect the summary block.
            if (fHaveSubblocks)
            {
                LOG(DAG, "%s(): mapsummaryUnlinked size before process new block: %ld", __func__,
                    mapSummaryBlocksUnlinked.size());
                mapSummaryBlocksUnlinked.erase(iter2);
                LEAVE_CRITICAL_SECTION(cs_forest);

                // locking cs_main here prevents any other thread from starting a block validation.
                {
                    LOCK(cs_main);
                    bool forceProcessing = true;
                    CValidationState state;
                    if (ProcessNewBlock(state, Params(), nullptr, pblock, forceProcessing, nullptr, false))
                        LOG(DAG, "%s(): process new block Passed", __func__);
                    else
                        LOG(DAG, "%s(): process new block FAILED", __func__);
                    LOG(DAG, "%s():done processing new block and trying to connect an orphaned summary block",
                        __func__);
                }
                ENTER_CRITICAL_SECTION(cs_forest);

                // Because we dropped the lock and took it again the iteration may now
                // have been invalidated by some other thread so set the iterator to the
                // beginning again. While theoretically it could be a very small performance
                // hit, in reality it's unlikely there will even be any other entries in the map
                // to process anyway.
                iter2 = mapSummaryBlocksUnlinked.begin();
                LOG(DAG, "%s(): mapsummaryUnlinked size after %ld", __func__, mapSummaryBlocksUnlinked.size());

                // Now check for any more orphaned subblocks that may connect to this newly connected
                // summary block.
                for (auto iter = mapNodesUnlinked.begin(); iter != mapNodesUnlinked.end();)
                {
                    assert(iter->second->subblock);

                    const uint256 &prev = iter->second->subblock->hashPrevBlock;
                    auto pindex = LookupBlockIndex(prev);
                    if ((pindex && pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) || mapAllGroves.count(prev))
                    {
                        LOG(DAG, "%s(): Process orphans - found orphan after summary block orphan %s", __func__,
                            iter->second->hash.ToString());
                        CTailstormGroveRef grove = nullptr;
                        if (_Insert(iter->second->subblock, grove))
                        {
                            setLinked.insert(iter->second->hash);

                            // The subblock was added to a grove and tree so update
                            // the global maps.
                            if (grove != nullptr)
                            {
                                mapAllGroves.emplace(iter->second->hash, grove);
                                mapAllGrovesByPrev.emplace(iter->second->subblock->hashPrevBlock, grove);
                            }
                            else
                                LOG(DAG, "%s(): WARNING: grove was nullptr", __func__);

                            mapNodesUnlinked.erase(iter);
                            iter = mapNodesUnlinked.begin();
                            continue;
                        }
                        else
                        {
                            LOG(DAG, "%s(): unlinked insert failed for %s size %ld", __func__,
                                iter->second->hash.ToString(), mapNodesUnlinked.size());
                        }
                    }
                    ++iter;
                }

                continue;
            }
        }

        iter2++;
    }

    return setLinked;
}

uint256 CTailstormForest::GetDagTipHash(const uint256 &hash)
{
    uint256 tiphash;
    if (GetBestTipHashFor(hash, tiphash))
        return tiphash;
    else
        return hash;
}

bool CTailstormForest::Find(const uint256 &hash, ConstCBlockRef &subblock)
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNodeRef>::iterator iter = mapAllNodes.find(hash);
    if (iter != mapAllNodes.end())
    {
        subblock = iter->second->subblock;
        return true;
    }
    return false;
}

bool CTailstormForest::Contains(const uint256 &hash)
{
    LOCK(cs_forest);
    return (mapAllNodes.count(hash) != 0);
}

std::map<uint256, CTreeNode> CTailstormForest::GetAllNodes()
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNode> allNodes;
    for (auto entry : mapAllNodes)
    {
        allNodes.emplace(entry.first, *entry.second);
    }
    return allNodes;
}

bool CTailstormForest::GetBestDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag)
{
    LOCK(cs_forest);
    auto iter = mapAllGrovesByPrev.find(hash);
    if (iter != mapAllGrovesByPrev.end())
    {
        if (!iter->second->GetBestDag(dag))
        {
            return false;
        }
        return true;
    }

    auto iter2 = mapAllGroves.find(hash);
    if (iter2 != mapAllGroves.end())
    {
        if (!iter2->second->GetBestDag(dag))
        {
            return false;
        }
        return true;
    }

    return false;
}

bool CTailstormForest::GetDagForBlock(ConstCBlockRef &pblock, std::set<CTreeNodeRef> &dag)
{
    LOCK(cs_forest);
    DbgAssert(IsSummaryBlock(*pblock), );

    bool fMatch = false;
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(pblock->hashPrevBlock, grove))
    {
        // Check each tree for a full set of treenodes that match the block. If we find
        // a match then break and return a positive result. If we don't match then keep
        // looking in any other trees than may be in the grove.
        auto subblockProofs = ParseMinerData(pblock->minerData);
        for (auto tree : grove->setValidTrees)
        {
            dag.clear();
            std::map<uint256, CTreeNodeRef> mapDagMiningHashes;

            // get all mining hashes in the tree
            for (auto mi : tree->dag)
            {
                const CTreeNodeRef &treenode = mi.second;
                const auto &miningHeaderCommitment = treenode->subblock->GetMiningHeaderCommitment();
                const auto &nonce = treenode->subblock->GetBlockHeader().nonce;
                mapDagMiningHashes.emplace(GetMiningHash(miningHeaderCommitment, nonce), treenode);
            }

            // does each minining hash in the block's minerDaga have a corresoponding one in the dag
            for (const auto &pair : subblockProofs)
            {
                const auto &miningHeaderCommitment = pair.first;
                const auto &nonce = pair.second;
                uint256 miningHash = GetMiningHash(miningHeaderCommitment, nonce);

                if (!mapDagMiningHashes.count(miningHash))
                {
                    // Check failed. If there is another tree then break and continue.
                    fMatch = false;
                    break;
                }
                else
                {
                    dag.insert(mapDagMiningHashes[miningHash]);
                    fMatch = true;
                }
            }
            if (fMatch)
            {
                break;
            }
        }

        if (!fMatch)
            dag.clear();
    }

    return fMatch;
}
bool CTailstormForest::GetBestTipHashFor(const uint256 &hash, uint256 &tiphash)
{
    LOCK(cs_forest);
    auto iter = mapAllGrovesByPrev.find(hash);
    if (iter != mapAllGrovesByPrev.end())
    {
        if (!iter->second->GetBestTipHash(tiphash))
        {
            return false;
        }
        return true;
    }

    auto iter2 = mapAllGroves.find(hash);
    if (iter2 != mapAllGroves.end())
    {
        if (!iter2->second->GetBestTipHash(tiphash))
        {
            return false;
        }
        return true;
    }

    return false;
}

void CTailstormForest::GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns)
{
    for (auto &iter : dag)
    {
        if (!iter->subblock)
            continue;

        for (CTransactionRef ptx : iter->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapDagTxns.emplace(ptx->GetId(), ptx);
        }
    }
    return;
}

uint32_t CTailstormForest::GetDagHeight(const uint256 &hash)
{
    LOCK(cs_forest);
    auto iter = mapAllNodes.find(hash);
    if (iter == mapAllNodes.end())
    {
        return 0;
    }
    else
    {
        return iter->second->dagHeight;
    }
}

bool CTailstormForest::GetGrove(const uint256 &hash, CTailstormGroveRef &grove)
{
    LOCK(cs_forest);
    auto iter = mapAllGrovesByPrev.find(hash);
    if (iter != mapAllGrovesByPrev.end())
    {
        grove = iter->second;
        return true;
    }

    auto iter2 = mapAllGroves.find(hash);
    if (iter2 != mapAllGroves.end())
    {
        grove = iter->second;
        return true;
    }

    return false;
}

void CTailstormForest::CheckForReorg()
{
    AssertLockNotHeld(cs_forest);

    // Only allow one thread to run re-org at a time.
    TRY_LOCK(cs_reorg, lock);
    if (!lock)
        return;

    uint256 BestDagSummaryRoot;
    {
        LOCK(cs_forest);

        // Get the current summary block height from chain active tip.
        uint64_t nSummaryBlockHeight = chainActive.Height();
        LOG(DAG, "%s(): summary block height %ld for %s", __func__, nSummaryBlockHeight,
            chainActive.Tip()->phashBlock->ToString());

        // Cycle through the forest looking for any subblocks at the current summary height and with dag height of
        // "1". Then save the previous block hash (which is the summary block this subblock is created on top of) to
        // a vector.
        std::set<uint256> vSummaryBlocks;
        LOG(DAG, "%s: starting vSummaryBlocks", __func__);
        // TODO: this loop could be simplified now that we store the blockindex of the summary root in the grove
        for (auto it_grove = mapAllGroves.begin(); it_grove != mapAllGroves.end(); it_grove++)
        {
            for (auto &iter : it_grove->second->mapGroveNodes)
            {
                if ((iter.second->dagHeight == 1))
                {
                    if (!iter.second->subblock)
                        continue;

                    const CBlockHeader &header = iter.second->subblock->GetBlockHeader();
                    if (header.height <= nSummaryBlockHeight)
                        continue;

                    vSummaryBlocks.insert(header.hashPrevBlock);
                    LOG(DAG, "%s():  subblock %s with a dagheight of 1 and header height of %d points to summary %s",
                        __func__, header.GetHash().ToString(), header.height, header.hashPrevBlock.ToString());
                }
            }
        }
        LOG(DAG, "%s: ending vSummaryBlocks", __func__);

        // Now we have all the summary block(s) at the chain active height.  If there is more
        // that one summary block we'll have to check if a re-org is needed. But if there's only
        // one summary block root then we can just return;
        if (vSummaryBlocks.size() <= 1)
        {
            LOG(DAG, "nothing to reorg");
            return;
        }
        LOG(DAG, "%s(): We have more than 1 summary at the chain tip : summary size %ld", __func__,
            vSummaryBlocks.size());

        // Find the best dag of all summary blocks and compare them for size and, if needed, initiate a
        // re-org to the summary block with the biggest dag. If there is a tie then stay on the current
        // chain tip.
        BestDagSummaryRoot = chainActive.Tip()->GetBlockHash();

        auto tailstorm_k = Params().GetConsensus().tailstorm_k;
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(BestDagSummaryRoot, dag);
        uint64_t nBestDagSize = dag.size() < tailstorm_k - 1 ? dag.size() : tailstorm_k - 1;
        LOG(DAG, "%s(): Best dag size for chain active %s is: %ld", __func__, BestDagSummaryRoot.ToString(),
            nBestDagSize);
        for (auto node : dag)
            LOG(DAG, "%s():    Subblock in chainactive dag: %s", __func__, node->hash.ToString());

        for (auto &hash : vSummaryBlocks)
        {
            LOG(DAG, "%s():  Check summary hash %s", __func__, hash.ToString());
            if (hash == BestDagSummaryRoot)
                continue;

            dag.clear();
            GetBestDagFor(hash, dag);
            uint64_t nDagSize = dag.size() < tailstorm_k - 1 ? dag.size() : tailstorm_k - 1;
            if (nDagSize > nBestDagSize)
            {
                nBestDagSize = nDagSize;
                BestDagSummaryRoot = hash;
                LOG(DAG, "%s():  Best summary root %s", __func__, hash.ToString());
                LOG(DAG, "%s():  Best summary root dag size is: %ld", __func__, nBestDagSize);
                for (auto node : dag)
                    LOG(DAG, "%s():     Subblock in dag: %s", __func__, node->hash.ToString());
            }
        }
    }

    // Initiate re-org if best dag is not on chain active.
    if (!BestDagSummaryRoot.IsNull() && (BestDagSummaryRoot != chainActive.Tip()->GetBlockHash()))
    {
        LOG(DAG, "%s(): Initiating a reorg", __func__);
        // Find the block index of the BestDagSummaryRoot hash and use this
        // as the pindexMostWork which gets passed to activate best chain step.
        CBlockIndex *pindexMostWork = LookupBlockIndex(BestDagSummaryRoot);

        if (!pindexMostWork)
        {
            LOG(DAG, "%s():  could not find pindexMostWork for reorg: %s", __func__, BestDagSummaryRoot.ToString());
            return;
        }

        if (pindexMostWork && !(pindexMostWork->nStatus & BLOCK_HAVE_DATA))
        {
            LOG(DAG, "%s():  WARNING: block data is not present for Reorg: %s", __func__,
                pindexMostWork->phashBlock->ToString());
            return;
        }

        LOG(DAG, "%s(): Initiating a reorg 2", __func__);
        LOCK(cs_main);
        CValidationState state;
        auto chainparams = Params();
        if (!ActivateBestChainStep(state, chainparams, pindexMostWork, nullptr, false))
        {
            LOG(DAG, "%s():  failed to reorg to %s", __func__, BestDagSummaryRoot.ToString());
        }
        else
            LOG(DAG, "%s(): Completed a reorg", __func__);
    }

    return;
}
