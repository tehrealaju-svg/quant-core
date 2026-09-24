// Transactions. The "core" part (inputs, outputs) is what the txid commits to and what every
// node stores forever. Signatures live in a separate witness section that nodes delete once a
// block is buried deep enough (signature pruning), which is where most of the bytes are.
#pragma once
#include <variant>

#include "util/serialize.h"

namespace quant {

struct OutPoint {
    Hash256 txid;
    uint32_t n = 0;
    auto operator<=>(const OutPoint&) const = default;
    bool operator==(const OutPoint&) const = default;
};
struct OutPointHasher {
    size_t operator()(const OutPoint& o) const noexcept { return Hash256Hasher{}(o.txid) ^ (size_t(o.n) * 0x9e3779b97f4a7c15ULL); }
};

struct TxIn {
    OutPoint prev;
};

// Output address versions. 0 = Falcon-512 key with a SPHINCS+ backup key.
constexpr uint8_t ADDR_V0 = 0;

struct TxOut {
    Amount value = 0;
    uint8_t addr_ver = ADDR_V0;
    Hash256 addr; // address_hash(falcon_pkhash, sphincs_pkhash)
};

// ---- witness (per input)
enum class WitnessType : uint8_t { Ref = 0, Falcon = 1, Sphincs = 2 };

struct WitnessRef { uint32_t input = 0; };        // same address as an earlier input -> reuse its signature
struct WitnessFalcon { Bytes falcon_pk; Hash256 sphincs_pkhash; Bytes sig; };
struct WitnessSphincs { Bytes sphincs_pk; Hash256 falcon_pkhash; Bytes sig; };
using Witness = std::variant<WitnessRef, WitnessFalcon, WitnessSphincs>;

struct Transaction {
    uint32_t version = 1;
    std::vector<TxIn> ins;
    std::vector<TxOut> outs;
    uint64_t lock_height = 0; // coinbase: must equal block height; otherwise earliest block height
    Bytes extra;              // coinbase only (miner tag / extra nonce), <= 100 bytes
    std::vector<Witness> witness; // one per input (empty for coinbase)

    bool is_coinbase() const { return ins.empty(); }

    void write_core(Writer& w) const;
    void write_witness(Writer& w) const;
    void write_full(Writer& w) const { write_core(w); write_witness(w); }
    static Transaction read_core(Reader& r);
    void read_witness(Reader& r);
    static Transaction read_full(Reader& r) { auto t = read_core(r); t.read_witness(r); return t; }

    Bytes core_bytes() const { Writer w; write_core(w); return w.buf; }
    Bytes witness_bytes() const { Writer w; write_witness(w); return w.buf; }
    Bytes full_bytes() const { Writer w; write_full(w); return w.buf; }
    size_t full_size() const { return full_bytes().size(); }

    Hash256 txid() const;
    Hash256 witness_hash() const;
    Amount total_out() const;
};

// Message signed by every input's key: binds the network (genesis) and the entire tx.
Hash256 signature_hash(const Hash256& genesis, const Hash256& txid);

} // namespace quant
