// Copyright (c) 2025 The TCCP developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TCCP_H
#define BITCOIN_TCCP_H

#include <cstddef>
#include <vector>
#include <uint256.h>

// Forward declarations to reduce compilation dependencies.
class CBlock;
class CBlockIndex;
namespace Consensus { struct Params; }


/**
 * TCCP encapsulates the logic for the Tightly-Coupled Capability Proof soft fork.
 */
namespace TCCP {

/**
 * Computes the TCCP proof P_i = MT-root(G(H(H(B_{i-1}) || M_real), SIZE_max)).
 * This is used by miners to generate the proof for a new block.
 */
uint256 ComputeProof(const uint256& prevBlockHash, const uint256& provisionalMerkleRoot, const Consensus::Params& params);

/**
 * Verifies the TCCP commitment within a given block.
 * This is the primary consensus-enforcement function called during block validation.
 */
bool VerifyBlock(const CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& params);

} // namespace TCCP

#endif // BITCOIN_TCCP_H
