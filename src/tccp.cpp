// Copyright (c) 2025 The TCCP developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tccp.h>

#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/bit_cast.h>

#include <vector>

namespace { // Anonymous namespace for internal linkage

/** A simple, deterministic Linear Congruential Generator (LCG) for V_chal. */
class LCG {
private:
    uint64_t m_state;
public:
    explicit LCG(const uint256& seed) { m_state = bit_cast<uint64_t>(seed); }
    uint32_t next() {
        m_state = 1664525 * m_state + 1013904223;
        return m_state >> 32;
    }
};

/** Computes the TCCP seed S_i = H(H(B_{i-1}) || M_real). */
uint256 CalculateSeed(const uint256& prevBlockHash, const uint256& merkleRoot) {
    CHash256 hasher;
    hasher.Write(prevBlockHash.begin(), prevBlockHash.size());
    hasher.Write(merkleRoot.begin(), merkleRoot.size());
    return hasher.GetHash();
}

/** Implements G(S_i, SIZE_max) to create a deterministic set of virtual transactions. */
std::vector<CTransactionRef> GenerateVirtualChallenge(const uint256& seed, size_t maxSize) {
    std::vector<CTransactionRef> virtualTxs;
    LCG prng(seed);
    size_t currentSize = 0;

    while (true) {
        CMutableTransaction mtx;
        mtx.nVersion = 1;
        mtx.nLockTime = 0;
        mtx.vin.resize(1);
        mtx.vin[0].prevout.hash = InsecureRand256();
        mtx.vin[0].prevout.n = prng.next() % 100;
        mtx.vin[0].scriptSig = CScript() << prng.next() << prng.next();
        std::vector<uint8_t> data(32);
        for (size_t i = 0; i < data.size(); ++i) { data[i] = prng.next() & 0xFF; }
        mtx.vout.resize(1);
        mtx.vout[0].nValue = Amount::zero();
        mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << data;

        const CTransactionRef tx = MakeTransactionRef(mtx);
        const size_t txSize = tx->GetTotalSize();
        if (currentSize + txSize > maxSize) break;
        virtualTxs.push_back(tx);
        currentSize += txSize;
    }
    return virtualTxs;
}

} // end anonymous namespace

namespace TCCP {

uint256 ComputeProof(const uint256& prevBlockHash, const uint256& provisionalMerkleRoot, const Consensus::Params& params) {
    const uint256 seed = CalculateSeed(prevBlockHash, provisionalMerkleRoot);
    const auto v_chal = GenerateVirtualChallenge(seed, params.nTCCPChallengeSize);
    if (v_chal.empty()) return uint256();
    
    std::vector<uint256> leaves;
    leaves.reserve(v_chal.size());
    for (const auto& tx : v_chal) {
        leaves.push_back(tx->GetHash());
    }
    return ComputeMerkleRoot(leaves);
}

bool VerifyBlock(const CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& params) {
    if (!pindexPrev) return true; // Genesis block is exempt

    const CTransaction& coinbaseTx = *block.vtx[0];
    uint256 submittedProof;
    int commitmentOutIndex = -1;

    for (size_t i = 0; i < coinbaseTx.vout.size(); ++i) {
        const CScript& script = coinbaseTx.vout[i].scriptPubKey;
        if (script.size() == 38 && script[0] == OP_RETURN && script[1] == 0x24) {
            std::vector<unsigned char> data(script.begin() + 2, script.end());
            if (std::vector<unsigned char>(data.begin(), data.begin() + 4) == TCCP_MAGIC_BYTES) {
                if (commitmentOutIndex != -1) return false;
                submittedProof = uint256(std::vector<unsigned char>(data.begin() + 4, data.end()));
                commitmentOutIndex = i;
            }
        }
    }

    if (commitmentOutIndex == -1) return false;

    uint256 M_real_reconstructed;
    {
        CMutableTransaction mtx_coinbase(coinbaseTx);
        mtx_coinbase.vout.erase(mtx_coinbase.vout.begin() + commitmentOutIndex);
        
        std::vector<CTransactionRef> vtx_temp = block.vtx;
        vtx_temp[0] = MakeTransactionRef(std::move(mtx_coinbase));
        M_real_reconstructed = BlockMerkleRoot(vtx_temp);
    }
    
    const uint256 expectedProof = ComputeProof(pindexPrev->GetBlockHash(), M_real_reconstructed, params);
    return submittedProof == expectedProof;
}

} // namespace TCCP
