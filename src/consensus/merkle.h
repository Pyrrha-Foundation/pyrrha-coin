// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CONSENSUS_MERKLE_H
#define NEXA_CONSENSUS_MERKLE_H

#include <stdint.h>
#include <vector>

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "uint256.h"

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool *mutated = nullptr);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock &block, bool *mutated = nullptr);
uint256 BlockMerkleRoot(const SatoshiBlock &block, bool *mutated = nullptr);

/*
 * Compute the Merkle branch for the tree of transactions in a block, for a
 * given position.
 * This can be verified using ComputeMerkleRootFromBranch.
 */
std::vector<uint256> BlockMerkleBranch(const CBlock &block, uint32_t position);
std::vector<uint256> BlockMerkleBranch(const SatoshiBlock &block, uint32_t position);

/*
 * Template class for merkle tree computation with different hashing functions
 * which may output hashes of different data size
 */
template <typename Hasher, typename Uint>
class Merkle
{
private:
  static void MerkleComputation(const std::vector<Uint> &leaves,
    Uint *proot,
    bool *pmutated,
    uint32_t branchpos,
    std::vector<Uint> *pbranch);

public:
  // inlined from hashwrapper.h
  template <typename T1, typename T2>
  inline static Uint Hash(const T1 p1begin, const T1 p1end, const T2 p2begin, const T2 p2end)
  {
      static const unsigned char pblank[1] = {};
      Uint result;
      Hasher()
          .Write(p1begin == p1end ? pblank : (const unsigned char *)&p1begin[0], (p1end - p1begin) * sizeof(p1begin[0]))
          .Write(p2begin == p2end ? pblank : (const unsigned char *)&p2begin[0], (p2end - p2begin) * sizeof(p2begin[0]))
          .Finalize((unsigned char *)&result);
      return result;
  }
  static std::vector<Uint> ComputeMerkleBranch(const std::vector<Uint> &leaves, uint32_t position);
  static Uint ComputeMerkleRootFromBranch(const Uint &leaf, const std::vector<Uint> &branch, uint32_t position);
};

/* This implements a constant-space merkle root/path calculator, limited to 2^32 leaves.

To compute a merkle root, pass -1 as the branchpos.

To compute a merkle path (AKA merkle proof), pass the index of the element being proved in branchpos.
pbranch will contain the merkle proof, not counting the element passed.
*/
template <typename Hasher, typename Uint>
void Merkle<Hasher, Uint>::MerkleComputation(const std::vector<Uint> &leaves,
    Uint *proot,
    bool *pmutated,
    uint32_t branchpos,
    std::vector<Uint> *pbranch)
{
    if (pbranch)
        pbranch->clear();
    if (leaves.size() == 0)
    {
        if (pmutated)
            *pmutated = false;
        if (proot)
            *proot = Uint();
        return;
    }
    bool mutated = false;
    // count is the number of leaves processed so far.
    uint32_t count = 0;
    // inner is an array of eagerly computed subtree hashes, indexed by tree
    // level (0 being the leaves).
    // For example, when count is 25 (11001 in binary), inner[4] is the hash of
    // the first 16 leaves, inner[3] of the next 8 leaves, and inner[0] equal to
    // the last leaf. The other inner entries are undefined.
    Uint inner[sizeof(Uint)];
    // Which position in inner is a hash that depends on the matching leaf.
    int matchlevel = -1;
    // First process all leaves into 'inner' values.
    while (count < leaves.size())
    {
        Uint h = leaves[count];
        bool matchh = count == branchpos;
        count++;
        int level;
        // For each of the lower bits in count that are 0, do 1 step. Each
        // corresponds to an inner value that existed before processing the
        // current leaf, and each needs a hash to combine it.
        for (level = 0; !(count & (((uint32_t)1) << level)); level++)
        {
            if (pbranch)
            {
                if (matchh)
                {
                    pbranch->push_back(inner[level]);
                }
                else if (matchlevel == level)
                {
                    pbranch->push_back(h);
                    matchh = true;
                }
            }
            mutated |= (inner[level] == h);
            Hasher().Write(inner[level].begin(), sizeof(Uint)).Write(h.begin(), sizeof(Uint)).Finalize(h.begin());
        }
        // Store the resulting hash at inner position level.
        inner[level] = h;
        if (matchh)
        {
            matchlevel = level;
        }
    }
    // Do a final 'sweep' over the rightmost branch of the tree to process
    // odd levels, and reduce everything to a single top value.
    // Level is the level (counted from the bottom) up to which we've sweeped.
    int level = 0;
    // As long as bit number level in count is zero, skip it. It means there
    // is nothing left at this level.
    while (!(count & (((uint32_t)1) << level)))
    {
        level++;
    }
    Uint h = inner[level];
    bool matchh = matchlevel == level;
    while (count != (((uint32_t)1) << level))
    {
        // If we reach this point, h is an inner value that is not the top.
        // We combine it with itself (Bitcoin's special rule for odd levels in
        // the tree) to produce a higher level one.
        if (pbranch && matchh)
        {
            pbranch->push_back(h);
        }
        Hasher().Write(h.begin(), sizeof(Uint)).Write(h.begin(), sizeof(Uint)).Finalize(h.begin());
        // Increment count to the value it would have if two entries at this
        // level had existed.
        count += (((uint32_t)1) << level);
        level++;
        // And propagate the result upwards accordingly.
        while (!(count & (((uint32_t)1) << level)))
        {
            if (pbranch)
            {
                if (matchh)
                {
                    pbranch->push_back(inner[level]);
                }
                else if (matchlevel == level)
                {
                    pbranch->push_back(h);
                    matchh = true;
                }
            }
            Hasher().Write(inner[level].begin(), sizeof(Uint)).Write(h.begin(), sizeof(Uint)).Finalize(h.begin());
            level++;
        }
    }
    // Return result.
    if (pmutated)
        *pmutated = mutated;
    if (proot)
        *proot = h;
}

/*
To compute a merkle path (AKA merkle proof), pass the index of the element being proved into position.
The merkle proof will be returned, not including the element.
For example, ComputeMerkleBranch(4 elements, 0) will return:
[ element[1], Hash256(element[2], element[3]) ]
*/
template <typename Hasher, typename Uint>
std::vector<Uint> Merkle<Hasher, Uint>::ComputeMerkleBranch(const std::vector<Uint> &leaves, uint32_t position)
{
    std::vector<Uint> ret;
    Merkle<Hasher, Uint>::MerkleComputation(leaves, nullptr, nullptr, position, &ret);
    return ret;
}

/* To verify a merkle proof, pass the hash of the element in "leaf", the merkle proof in "branch", and the zero-based
index specifying where the element was in the array when the merkle proof was created.
*/
template <typename Hasher, typename Uint>
Uint Merkle<Hasher, Uint>::ComputeMerkleRootFromBranch(const Uint &leaf, const std::vector<Uint> &vMerkleBranch, uint32_t nIndex)
{
    Uint hash = leaf;
    for (typename std::vector<Uint>::const_iterator it = vMerkleBranch.begin(); it != vMerkleBranch.end(); ++it)
    {
        if (nIndex & 1)
        {
            hash = Merkle<Hasher, Uint>::Hash<char *, char *>(BEGIN(*it), END(*it), BEGIN(hash), END(hash));
        }
        else
        {
            hash = Merkle<Hasher, Uint>::Hash<char *, char *>(BEGIN(hash), END(hash), BEGIN(*it), END(*it));
        }
        nIndex >>= 1;
    }
    return hash;
}

/* Given the serialized Merkle proof, return the vector of proof elements, aka Merkle branch
 * Helper function for OP_MERKLE
*/
template <typename Uint>
inline std::vector<Uint> RawProofToBranch(const VchType &proof) {
  std::vector<Uint> branch;
  branch.reserve(proof.size() / sizeof(Uint));
  for (auto it = proof.begin(); it < proof.end(); it += sizeof(Uint)) {
      branch.emplace_back(Uint(&(*it)));
  }

  return branch;
}

typedef Merkle<CHash256, uint256> MerkleHash256;
typedef Merkle<CHash160, uint160> MerkleHash160;

inline const auto& ComputeMerkleBranch = MerkleHash256::ComputeMerkleBranch;
inline const auto& ComputeMerkleRootFromBranch = MerkleHash256::ComputeMerkleRootFromBranch;

#endif // NEXA_CONSENSUS_MERKLE_H
