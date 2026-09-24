#include "primitives/block.h"

#include "consensus/limits.h"
#include "crypto/hash.h"

namespace quant {

void BlockHeader::write(Writer& w) const {
    w.u32le(version); w.hash(prev); w.hash(merkle_root); w.hash(witness_root);
    w.u64le(time); w.u32le(bits); w.u64le(nonce);
}

BlockHeader BlockHeader::read(Reader& r) {
    BlockHeader h;
    h.version = r.u32le(); h.prev = r.hash(); h.merkle_root = r.hash(); h.witness_root = r.hash();
    h.time = r.u64le(); h.bits = r.u32le(); h.nonce = r.u64le();
    return h;
}

void BlockHeader::serialize(uint8_t out[SIZE]) const {
    Writer w; write(w);
    std::memcpy(out, w.buf.data(), SIZE);
}

Hash256 BlockHeader::hash() const {
    uint8_t b[SIZE];
    serialize(b);
    return blake3(b, SIZE);
}

Bytes Block::core_bytes() const {
    Writer w;
    header.write(w);
    w.varint(txs.size());
    for (auto& t : txs) t.write_core(w);
    return w.buf;
}

Bytes Block::witness_bytes() const {
    Writer w;
    for (auto& t : txs) t.write_witness(w);
    return w.buf;
}

Bytes Block::full_bytes() const {
    Bytes b = core_bytes();
    Bytes wb = witness_bytes();
    b.insert(b.end(), wb.begin(), wb.end());
    return b;
}

Block Block::read_core(Reader& r) {
    Block b;
    b.header = BlockHeader::read(r);
    size_t n = r.varint_max(MAX_BLOCK_SIZE / 40);
    b.txs.reserve(n);
    for (size_t i = 0; i < n; i++) b.txs.push_back(Transaction::read_core(r));
    return b;
}

void Block::read_witness(Reader& r) {
    for (auto& t : txs) t.read_witness(r);
}

Hash256 Block::compute_merkle_root() const {
    std::vector<Hash256> l;
    l.reserve(txs.size());
    for (auto& t : txs) l.push_back(t.txid());
    return merkle_root(std::move(l));
}

Hash256 Block::compute_witness_root() const {
    std::vector<Hash256> l;
    l.reserve(txs.size());
    for (auto& t : txs) l.push_back(t.witness_hash());
    return merkle_root(std::move(l));
}

static Hash256 merkle_node(const Hash256& a, const Hash256& b) {
    uint8_t buf[64];
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    return blake3_tagged(ctx::MERKLE, buf, 64);
}

Hash256 merkle_root(std::vector<Hash256> l) {
    if (l.empty()) return Hash256{};
    while (l.size() > 1) {
        std::vector<Hash256> next;
        for (size_t i = 0; i < l.size(); i += 2)
            next.push_back(i + 1 < l.size() ? merkle_node(l[i], l[i + 1]) : l[i]);
        l = std::move(next);
    }
    return l[0];
}

std::vector<Hash256> merkle_proof(const std::vector<Hash256>& leaves, size_t index) {
    std::vector<Hash256> proof;
    std::vector<Hash256> l = leaves;
    while (l.size() > 1) {
        size_t sib = index ^ 1;
        proof.push_back(sib < l.size() ? l[sib] : Hash256{});
        std::vector<Hash256> next;
        for (size_t i = 0; i < l.size(); i += 2)
            next.push_back(i + 1 < l.size() ? merkle_node(l[i], l[i + 1]) : l[i]);
        l = std::move(next);
        index /= 2;
    }
    return proof;
}

bool merkle_verify(const Hash256& leaf, size_t index, size_t count, const std::vector<Hash256>& proof, const Hash256& root) {
    if (index >= count) return false;
    Hash256 h = leaf;
    size_t level = 0, n = count;
    while (n > 1) {
        if (level >= proof.size()) return false;
        size_t sib = index ^ 1;
        if (sib < n) h = (index & 1) ? merkle_node(proof[level], h) : merkle_node(h, proof[level]);
        else if (!proof[level].is_zero()) return false;
        index /= 2; n = (n + 1) / 2; level++;
    }
    return level == proof.size() && h == root;
}

} // namespace quant
