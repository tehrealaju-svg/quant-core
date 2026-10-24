// Transactions. The "core" part (inputs, outputs, token ops) is what the txid commits to and
// what every node stores. Signatures live in a separate witness section that nodes delete once
// a block is buried deep enough (signature pruning), which is where most of the bytes are.
//
// Every output carries an asset: QNT (zero id) or a token. Token ops let a transaction mint a
// new token or trade against the on-chain constant-product pools. Each op declares the exact
// amounts it moves; consensus checks those amounts are allowed by the pool math, and that every
// asset balances: inputs + what ops release == outputs + what ops take in (QNT may leave a fee).
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

// Asset id: all zero = QNT.
inline const Hash256 QNT_ASSET{};

struct TxOut {
    Amount value = 0;
    Hash256 asset;  // QNT_ASSET or a token / pool-share id
    Hash256 addr;   // address_hash(falcon_pk)
    bool is_qnt() const { return asset.is_zero(); }
};

// ---- token ops
enum class OpType : uint8_t { CreateToken = 1, PoolCreate = 2, AddLiquidity = 3, RemoveLiquidity = 4, Swap = 5 };

struct OpCreateToken {          // mints `supply` of a brand-new token into this tx's outputs
    std::string ticker;         // 1-10 chars A-Z 0-9
    std::string name;           // 1-32 printable chars
    uint8_t decimals = 8;       // 0-10
    Amount supply = 0;
    std::string uri;            // optional logo / website, <= 120 chars
};
struct OpPoolCreate {           // opens the QNT/token pool with the first liquidity
    Hash256 token;
    Amount qnt = 0, tok = 0;    // deposited
    Amount shares = 0;          // pool shares minted to outputs (<= sqrt(qnt*tok) - MIN_LIQUIDITY)
};
struct OpAddLiquidity {
    Hash256 token;
    Amount qnt = 0, tok = 0;    // deposited
    Amount shares = 0;          // <= min(qnt*S/Rq, tok*S/Rt)
};
struct OpRemoveLiquidity {
    Hash256 token;
    Amount shares = 0;          // burned
    Amount qnt = 0, tok = 0;    // withdrawn, each <= shares * reserve / S
};
struct OpSwap {
    Hash256 token;
    bool sell = false;          // false: QNT in, token out. true: token in, QNT out.
    Amount in = 0;
    Amount out = 0;             // <= constant-product quote after the 0.3% pool fee
};
using TxOp = std::variant<OpCreateToken, OpPoolCreate, OpAddLiquidity, OpRemoveLiquidity, OpSwap>;

// ---- witness (per input)
enum class WitnessType : uint8_t { Ref = 0, Falcon = 1 };
struct WitnessRef { uint32_t input = 0; };   // same address as an earlier input -> reuse its signature
struct WitnessFalcon { Bytes pk; Bytes sig; };
using Witness = std::variant<WitnessRef, WitnessFalcon>;

struct Transaction {
    uint32_t version = 2;
    std::vector<TxIn> ins;
    std::vector<TxOut> outs;
    std::vector<TxOp> ops;
    uint64_t lock_height = 0;     // coinbase: must equal block height; otherwise earliest block height
    Bytes extra;                  // coinbase only (miner tag / extra nonce), <= 100 bytes
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
    Amount total_qnt_out() const;
};

// Canonical encoding of one output (also used by the p2p light-wallet messages).
void write_txout(Writer& w, const TxOut& o);
TxOut read_txout(Reader& r);

// Id of the token created by op `op_index` of a tx whose first input is `first_in`.
// (Derived from the input, not the txid, so the tx's own outputs can name it.)
Hash256 token_id(const OutPoint& first_in, uint32_t op_index);
// Id of the share token of the QNT/token pool.
Hash256 pool_share_id(const Hash256& token);

// Message signed by every input's key: binds the network (genesis) and the entire tx.
Hash256 signature_hash(const Hash256& genesis, const Hash256& txid);

} // namespace quant
