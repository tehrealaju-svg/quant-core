#include "primitives/transaction.h"

#include "consensus/limits.h"
#include "crypto/hash.h"
#include "crypto/sig.h"

namespace quant {

void Transaction::write_core(Writer& w) const {
    w.varint(version);
    w.varint(ins.size());
    for (auto& in : ins) { w.hash(in.prev.txid); w.varint(in.prev.n); }
    w.varint(outs.size());
    for (auto& o : outs) { w.varint(o.value); w.u8(o.addr_ver); w.hash(o.addr); }
    w.varint(lock_height);
    w.bytes(extra);
}

void Transaction::write_witness(Writer& w) const {
    w.varint(witness.size());
    for (auto& wit : witness) {
        if (auto* r = std::get_if<WitnessRef>(&wit)) {
            w.u8(uint8_t(WitnessType::Ref)); w.varint(r->input);
        } else if (auto* f = std::get_if<WitnessFalcon>(&wit)) {
            w.u8(uint8_t(WitnessType::Falcon)); w.raw(f->falcon_pk); w.hash(f->sphincs_pkhash); w.bytes(f->sig);
        } else if (auto* s = std::get_if<WitnessSphincs>(&wit)) {
            w.u8(uint8_t(WitnessType::Sphincs)); w.raw(s->sphincs_pk); w.hash(s->falcon_pkhash); w.raw(s->sig);
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
    t.outs.resize(nout);
    for (auto& o : t.outs) { o.value = r.varint(); o.addr_ver = r.u8(); o.addr = r.hash(); }
    t.lock_height = r.varint();
    t.extra = r.bytes(MAX_COINBASE_EXTRA);
    return t;
}

void Transaction::read_witness(Reader& r) {
    size_t n = r.varint_max(MAX_TX_INPUTS);
    witness.clear();
    witness.reserve(n);
    for (size_t i = 0; i < n; i++) {
        uint8_t type = r.u8();
        switch (WitnessType(type)) {
        case WitnessType::Ref: witness.push_back(WitnessRef{uint32_t(r.varint_max(MAX_TX_INPUTS))}); break;
        case WitnessType::Falcon: {
            WitnessFalcon f;
            f.falcon_pk = r.raw(FALCON_PK_BYTES);
            f.sphincs_pkhash = r.hash();
            f.sig = r.bytes(FALCON_SIG_MAX);
            witness.push_back(std::move(f));
            break;
        }
        case WitnessType::Sphincs: {
            WitnessSphincs s;
            s.sphincs_pk = r.raw(SPHINCS_PK_BYTES);
            s.falcon_pkhash = r.hash();
            s.sig = r.raw(SPHINCS_SIG_BYTES);
            witness.push_back(std::move(s));
            break;
        }
        default: throw SerializeError("unknown witness type");
        }
    }
}

Hash256 Transaction::txid() const { return blake3_tagged(ctx::TXID, core_bytes()); }
Hash256 Transaction::witness_hash() const { return blake3_tagged(ctx::WTXID, witness_bytes()); }

Amount Transaction::total_out() const {
    Amount s = 0;
    for (auto& o : outs) s += o.value;
    return s;
}

Hash256 signature_hash(const Hash256& genesis, const Hash256& txid) {
    uint8_t buf[64];
    std::memcpy(buf, genesis.data(), 32);
    std::memcpy(buf + 32, txid.data(), 32);
    return blake3_tagged(ctx::SIGHASH, buf, 64);
}

} // namespace quant
