#include "primitives/transaction.h"

#include "consensus/limits.h"
#include "crypto/hash.h"
#include "crypto/sig.h"

namespace quant {

// Outputs: the asset is a 1-byte flag (0 = QNT) followed by the id for tokens, so plain QNT
// payments cost nothing extra.
void write_txout(Writer& w, const TxOut& o) {
    w.varint(o.value);
    if (o.is_qnt()) w.u8(0); else { w.u8(1); w.hash(o.asset); }
    w.hash(o.addr);
}
TxOut read_txout(Reader& r) {
    TxOut o;
    o.value = r.varint();
    uint8_t f = r.u8();
    if (f == 1) { o.asset = r.hash(); if (o.asset.is_zero()) throw SerializeError("non-canonical asset"); }
    else if (f != 0) throw SerializeError("bad asset flag");
    o.addr = r.hash();
    return o;
}

static void write_op(Writer& w, const TxOp& op) {
    std::visit([&](auto& o) {
        using T = std::decay_t<decltype(o)>;
        if constexpr (std::is_same_v<T, OpCreateToken>) {
            w.u8(uint8_t(OpType::CreateToken)); w.str(o.ticker); w.str(o.name); w.u8(o.decimals); w.varint(o.supply); w.str(o.uri);
        } else if constexpr (std::is_same_v<T, OpPoolCreate>) {
            w.u8(uint8_t(OpType::PoolCreate)); w.hash(o.token); w.varint(o.qnt); w.varint(o.tok); w.varint(o.shares);
        } else if constexpr (std::is_same_v<T, OpAddLiquidity>) {
            w.u8(uint8_t(OpType::AddLiquidity)); w.hash(o.token); w.varint(o.qnt); w.varint(o.tok); w.varint(o.shares);
        } else if constexpr (std::is_same_v<T, OpRemoveLiquidity>) {
            w.u8(uint8_t(OpType::RemoveLiquidity)); w.hash(o.token); w.varint(o.shares); w.varint(o.qnt); w.varint(o.tok);
        } else if constexpr (std::is_same_v<T, OpSwap>) {
            w.u8(uint8_t(OpType::Swap)); w.hash(o.token); w.u8(o.sell ? 1 : 0); w.varint(o.in); w.varint(o.out);
        }
    }, op);
}

static TxOp read_op(Reader& r) {
    switch (OpType(r.u8())) {
    case OpType::CreateToken: {
        OpCreateToken o;
        o.ticker = r.str(MAX_TICKER); o.name = r.str(MAX_TOKEN_NAME); o.decimals = r.u8(); o.supply = r.varint(); o.uri = r.str(MAX_TOKEN_URI);
        return o;
    }
    case OpType::PoolCreate: { OpPoolCreate o; o.token = r.hash(); o.qnt = r.varint(); o.tok = r.varint(); o.shares = r.varint(); return o; }
    case OpType::AddLiquidity: { OpAddLiquidity o; o.token = r.hash(); o.qnt = r.varint(); o.tok = r.varint(); o.shares = r.varint(); return o; }
    case OpType::RemoveLiquidity: { OpRemoveLiquidity o; o.token = r.hash(); o.shares = r.varint(); o.qnt = r.varint(); o.tok = r.varint(); return o; }
    case OpType::Swap: {
        OpSwap o; o.token = r.hash();
        uint8_t s = r.u8(); if (s > 1) throw SerializeError("bad swap direction");
        o.sell = s == 1; o.in = r.varint(); o.out = r.varint();
        return o;
    }
    }
    throw SerializeError("unknown op");
}

void Transaction::write_core(Writer& w) const {
    w.varint(version);
    w.varint(ins.size());
    for (auto& in : ins) { w.hash(in.prev.txid); w.varint(in.prev.n); }
    w.varint(outs.size());
    for (auto& o : outs) write_txout(w, o);
    w.varint(ops.size());
    for (auto& op : ops) write_op(w, op);
    w.varint(lock_height);
    w.bytes(extra);
}

void Transaction::write_witness(Writer& w) const {
    w.varint(witness.size());
    for (auto& wit : witness) {
        if (auto* r = std::get_if<WitnessRef>(&wit)) {
            w.u8(uint8_t(WitnessType::Ref)); w.varint(r->input);
        } else if (auto* f = std::get_if<WitnessFalcon>(&wit)) {
            w.u8(uint8_t(WitnessType::Falcon)); w.raw(f->pk); w.bytes(f->sig);
        }
    }
}

Transaction Transaction::read_core(Reader& r) {
    Transaction t;
    t.version = uint32_t(r.varint_max(0xffffffff));
    size_t nin = r.varint_max(MAX_TX_INPUTS);
    t.ins.resize(nin);
    for (auto& in : t.ins) { in.prev.txid = r.hash(); in.prev.n = uint32_t(r.varint_max(0xffffffff)); }
    size_t nout = r.varint_max(MAX_TX_OUTPUTS);
    t.outs.reserve(nout);
    for (size_t i = 0; i < nout; i++) t.outs.push_back(read_txout(r));
    size_t nops = r.varint_max(MAX_TX_OPS);
    for (size_t i = 0; i < nops; i++) t.ops.push_back(read_op(r));
    t.lock_height = r.varint();
    t.extra = r.bytes(MAX_COINBASE_EXTRA);
    return t;
}

void Transaction::read_witness(Reader& r) {
    size_t n = r.varint_max(MAX_TX_INPUTS);
    witness.clear();
    witness.reserve(n);
    for (size_t i = 0; i < n; i++) {
        switch (WitnessType(r.u8())) {
        case WitnessType::Ref: witness.push_back(WitnessRef{uint32_t(r.varint_max(MAX_TX_INPUTS))}); break;
        case WitnessType::Falcon: {
            WitnessFalcon f;
            f.pk = r.raw(FALCON_PK_BYTES);
            f.sig = r.bytes(FALCON_SIG_MAX);
            witness.push_back(std::move(f));
            break;
        }
        default: throw SerializeError("unknown witness type");
        }
    }
}

Hash256 Transaction::txid() const { return blake3_tagged(ctx::TXID, core_bytes()); }
Hash256 Transaction::witness_hash() const { return blake3_tagged(ctx::WTXID, witness_bytes()); }

Amount Transaction::total_qnt_out() const {
    Amount s = 0;
    for (auto& o : outs) if (o.is_qnt()) s += o.value;
    return s;
}

Hash256 token_id(const OutPoint& first_in, uint32_t op_index) {
    Writer w;
    w.hash(first_in.txid); w.u32le(first_in.n); w.u32le(op_index);
    return blake3_tagged(ctx::ASSET, w.buf);
}

Hash256 pool_share_id(const Hash256& token) { return blake3_tagged(ctx::LPTOKEN, token.data(), 32); }

Hash256 signature_hash(const Hash256& genesis, const Hash256& txid) {
    uint8_t buf[64];
    std::memcpy(buf, genesis.data(), 32);
    std::memcpy(buf + 32, txid.data(), 32);
    return blake3_tagged(ctx::SIGHASH, buf, 64);
}

} // namespace quant
