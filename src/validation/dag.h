// Copyright (c) 2020-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TAILSTORM_DAG_H
#define NEXA_TAILSTORM_DAG_H


#include "chain.h"
#include "coins.h"
#include "primitives/block.h"
#include "sync.h"

#include <deque>
#include <queue>
#include <set>

extern CChain chainActive;
extern CCoinsViewCache *pcoinsTip;

class CTreeNode;
typedef std::shared_ptr<CTreeNode> CTreeNodeRef;
template <typename Node>
static inline CTreeNodeRef MakeTreeNodeRef(Node &&nodeIn)
{
    return std::make_shared<CTreeNode>(std::forward<Node>(nodeIn));
}
class CTailstormGrove;
typedef std::shared_ptr<CTailstormGrove> CTailstormGroveRef;
template <typename Grove>
static inline CTailstormGroveRef MakeTailstormGroveRef(Grove &&groveIn)
{
    return std::make_shared<CTailstormGrove>(std::forward<Grove>(groveIn));
}

// CTreeNode has a header only implementation
class CTreeNode
{
public:
    uint256 hash; // the subblock hash that is this node
    uint32_t dagHeight;
    uint32_t nSequenceId;

    ConstCBlockRef subblock = nullptr;

    CTreeNodeRef ancestor; // should point to the node of the parentHash
    std::set<CTreeNodeRef> vDescendents; // points to the nodes of the children

private:
    CTreeNode() {} // disable default constructor

public:
    CTreeNode(ConstCBlockRef _subblock)
    {
        hash = _subblock->GetHash();
        subblock = _subblock;
        dagHeight = 0;
        nSequenceId = 0;
    }

    friend bool operator<(const CTreeNode a, const CTreeNode b) { return a.hash < b.hash; }

    void AddAncestor(CTreeNodeRef _ancestor) { ancestor = _ancestor; }
    void AddDescendant(CTreeNodeRef _descendent) { vDescendents.emplace(_descendent); }

    // This subblock is just after the last summary block
    bool IsBase() { return (ancestor == nullptr && dagHeight == 1); }

    // This subblock is a tree tip
    bool IsTip() { return vDescendents.empty(); }
};

class CTailstormTree
{
    friend class CTailstormGrove;
    friend class CTailstormForest;

protected:
    // pointers point to the nodes for this dag, a pointer to the same node is
    // also available in mapAllNodes at the forest level
    std::map<uint256, CTreeNodeRef> dag;

    // map of unique transactions that are already in the dag for this tree
    std::map<uint256, CTransactionRef> mapDagTxns;

    // global coins cache pointer
    CCoinsViewCache *_pcoinsTip = nullptr;

    // coins cache view for the this tree backed by _pcoinsTip
    CCoinsViewCache *view = nullptr;

    // the block index of the summary block that this tree is built on top of.
    CBlockIndex *pindexSummaryRoot = nullptr;

public:
    CTailstormTree() {}
    ~CTailstormTree()
    {
        if (view)
        {
            delete view;
            view = nullptr;
        }
    }

protected:
    bool Insert(CTreeNodeRef new_node, bool *fAllowRecursion = nullptr);
};

// this class can not have any public data members, all datamembers are
// protected by cs_forest
class CTailstormGrove
{
    friend class CTailstormForest;
    friend class CTailstormTree;

protected:
    // There can be many valid trees in a grove but, "tree" references the current active tree.
    std::shared_ptr<CTailstormTree> tree = nullptr;

    // The set of valid trees.
    std::set<std::shared_ptr<CTailstormTree> > setValidTrees;

    // key is subblock hash for the node in value
    std::map<uint256, CTreeNodeRef> mapGroveNodes;

    // the hash of the summary block that this grove is being built on top of
    uint256 roothash;

    CCoinsViewCache *_pcoinsTip;

protected:
    bool InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache);
    bool InsertIntoTree(CTreeNodeRef newNode);

    CTailstormGrove(CCoinsViewCache *coinsCache)
    {
        CTailstormTree temp;
        tree = std::make_shared<CTailstormTree>(temp);
        setValidTrees.insert(tree);

        _pcoinsTip = coinsCache;
        assert(_pcoinsTip);
    }

    void Clear();

    bool Insert(CTreeNodeRef newNode);
    bool GetBestDag(std::set<CTreeNodeRef> &dag);
    bool GetBestTipHash(uint256 &hash);
    void ActivateBestTree();
};

class CTailstormForest
{
    friend class CTailstormGrove;

public:
    CCriticalSection cs_forest;

    // Used for try locking when we check for a re-org
    // to limit execution to one thread.
    CCriticalSection cs_reorg;

protected:
    // key is subblock hash for the node in value
    // mapAllNodes contains all nodes in the entire forest including orphans. The grove contains two
    // maps that are a subsets of this map. They are only used to speed up grove
    // specific node searching and for faster cleanup of nodes being removed
    // from the forest
    std::map<uint256, CTreeNodeRef> mapAllNodes;

    // Used for finding which grove a subblock is in by the subblocks prev block hash.
    std::map<uint256, CTailstormGroveRef> mapAllGrovesByPrev;

    // Used for finding which grove a subblock is in by hash
    std::map<uint256, CTailstormGroveRef> mapAllGroves;

    // Contains all orphan nodes
    std::map<uint256, CTreeNodeRef> mapNodesUnlinked;

    // Contains all orphaned summary blocks
    std::map<uint256, ConstCBlockRef> mapSummaryBlocksUnlinked;

    CCoinsViewCache *_pcoinsTip;

public:
    CTailstormForest() {}
    ~CTailstormForest() { Clear(); }

    //! Clear all forest, grove and tree data structures.
    void Clear();

    //! Clear a grove that has the passed hash in it.
    void ClearGrove(const uint256 &hash);

    //! Trim the forest of any nodes <= nPruneHeight
    void ClearByHeight(const uint32_t nPruneHeight);

    //! The number of nodes in the forest
    size_t Size();

    //! Insert a new subblock into a grove
    bool Insert(ConstCBlockRef subblock, CTailstormGroveRef &grove);
    bool _Insert(ConstCBlockRef subblock, CTailstormGroveRef &grove);

    /** Add a summary block which can't be connected yet because all
     * subblocks reference in the minerData have not yet been received.
     */
    void AddSummaryBlockOrphan(ConstCBlockRef pblock);

    //! Process all orphaned subblocks and summary blocks
    std::set<uint256> ProcessOrphans();

    //! Return a hash of the dag tip given a hash of some subblock in the dag.
    uint256 GetDagTipHash(const uint256 &hash);

    //! Find and return a subblock in the forest, if it exists.
    bool Find(const uint256 &hash, ConstCBlockRef &subblock);

    //! Find out whether the forst contains a treenode
    bool Contains(const uint256 &hash);

    //! return a map of all tree nodes.
    std::map<uint256, CTreeNode> GetAllNodes();

    //! Return a set of tree nodes of the best dag
    bool GetBestDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag);

    //! Return a set of nodes from a tree that matches what is in a block
    bool GetDagForBlock(ConstCBlockRef &pblock, std::set<CTreeNodeRef> &dag);

    //! Return the current hash of the tip of the best dag
    bool GetBestTipHashFor(const uint256 &hash, uint256 &tiphash);

    //! Return a map of all the transactions in the given dag
    void GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns);

    //! Return the dag height of a subblock given it's hash.
    uint32_t GetDagHeight(const uint256 &hash);

    //! Return a the grove that a subblock belongs to
    bool GetGrove(const uint256 &hash, CTailstormGroveRef &grove);

    //! Detemine if we need to re-org the chainActive tip to one that has a better dag.
    void CheckForReorg();

    //! Set the main coins cache that we build our tailstorm tree views on top of.
    void SetBackend(CCoinsViewCache *coinsCache) { _pcoinsTip = coinsCache; };
};

extern CTailstormForest tailstormForest;

// Helper Function: Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &setBestDag);

#endif
