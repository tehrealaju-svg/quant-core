#pragma once
#include "primitives/transaction.h"

namespace quant {

// Fixed 120-byte header. Its plain BLAKE3 hash is both the block id and the proof of work.
struct BlockHeader {
    uint32_t version = 1;
    Hash256 prev;
    Hash256 merkle_root;   // over txids (core data)
    Hash256 witness_root;  // over per-tx witness hashes (prunable data)
    uint64_t time = 0;
    uint32_t bits = 0;
    uint64_t nonce = 0;

    static constexpr size_t SIZE = 4 + 32 + 32 + 32 + 8 + 4 + 8;
    void write(Writer& w) const;
    static BlockHeader read(Reader& r);
    void serialize(uint8_t out[SIZE]) const;
    Hash256 hash() const;
};

struct Block {
    BlockHeader header;
    std::vector<Transaction> txs;

    // Core = header + tx cores. Witness = all tx witnesses. Full = both (wire format).
    Bytes core_bytes() const;
    Bytes witness_bytes() const;
    Bytes full_bytes() const;
    static Block read_core(Reader& r);
    void read_witness(Reader& r);
    static Block read_full(Reader& r) { auto b = read_core(r); b.read_witness(r); return b; }
    size_t full_size() const { return full_bytes().size(); }

    Hash256 compute_merkle_root() const;
    Hash256 compute_witness_root() const;
};

// Merkle tree with domain-separated inner nodes; an odd node is carried up unchanged
// (no duplication, which avoids Bitcoin's CVE-2012-2459 ambiguity).
Hash256 merkle_root(std::vector<Hash256> leaves);
// Proof for leaf `index`: sibling hashes bottom-up; a zero hash marks "no sibling" (carried).
std::vector<Hash256> merkle_proof(const std::vector<Hash256>& leaves, size_t index);
bool merkle_verify(const Hash256& leaf, size_t index, size_t count, const std::vector<Hash256>& proof, const Hash256& root);

} // namespace quant
