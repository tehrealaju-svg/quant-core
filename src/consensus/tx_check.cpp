#include "consensus/tx_check.h"

#include <set>

#include "consensus/limits.h"
#include "crypto/sig.h"

namespace quant {

TxResult check_tx_basic(const Transaction& tx, bool expect_witness) {
    if (tx.version != 1) return TxResult::fail("bad-version");
    if (tx.outs.empty() && !tx.is_coinbase()) return TxResult::fail("no-outputs"); // coinbase may be empty once rewards end
    if (tx.is_coinbase()) {
        if (!tx.witness.empty()) return TxResult::fail("coinbase-witness");
    } else {
        if (!tx.extra.empty()) return TxResult::fail("extra-in-non-coinbase");
        if (expect_witness && tx.witness.size() != tx.ins.size()) return TxResult::fail("witness-count");
        std::set<OutPoint> seen;
        for (auto& in : tx.ins)
            if (!seen.insert(in.prev).second) return TxResult::fail("duplicate-input");
    }
    Amount total = 0;
    for (auto& o : tx.outs) {
        if (o.addr_ver != ADDR_V0) return TxResult::fail("unknown-address-version");
        if (o.value == 0) return TxResult::fail("zero-output");
        if (!tx.is_coinbase() && o.value < DUST_LIMIT) return TxResult::fail("dust-output");
        if (o.value > MAX_MONEY) return TxResult::fail("output-too-large");
        total += o.value;
        if (total > MAX_MONEY) return TxResult::fail("outputs-overflow");
    }
    return {};
}

bool verify_witness(const Transaction& tx, const std::vector<Coin>& coins, const Hash256& genesis, std::string* why) {
    auto fail = [&](const char* r) { if (why) *why = r; return false; };
    if (tx.witness.size() != tx.ins.size()) return fail("witness-count");
    Hash256 sighash = signature_hash(genesis, tx.txid());
    for (size_t i = 0; i < tx.ins.size(); i++) {
        const Hash256& addr = coins[i].out.addr;
        const Witness& w = tx.witness[i];
        if (auto* r = std::get_if<WitnessRef>(&w)) {
            // Reuse the signature of an earlier input that pays to the same address.
            if (r->input >= i) return fail("ref-forward");
            if (std::holds_alternative<WitnessRef>(tx.witness[r->input])) return fail("ref-chain");
            if (coins[r->input].out.addr != addr) return fail("ref-address-mismatch");
        } else if (auto* f = std::get_if<WitnessFalcon>(&w)) {
            if (address_hash(pubkey_hash(f->falcon_pk), f->sphincs_pkhash) != addr) return fail("falcon-key-mismatch");
            if (!falcon_verify(f->falcon_pk, f->sig, sighash)) return fail("falcon-bad-signature");
        } else if (auto* s = std::get_if<WitnessSphincs>(&w)) {
            if (address_hash(s->falcon_pkhash, pubkey_hash(s->sphincs_pk)) != addr) return fail("sphincs-key-mismatch");
            if (!sphincs_verify(s->sphincs_pk, s->sig, sighash)) return fail("sphincs-bad-signature");
        }
    }
    return true;
}

TxResult check_tx_inputs(const Transaction& tx, const std::vector<Coin>& coins, uint64_t height,
                         const Hash256& genesis, bool verify_sigs) {
    if (tx.is_coinbase()) return TxResult::fail("coinbase-in-check-inputs");
    if (coins.size() != tx.ins.size()) return TxResult::fail("missing-inputs");
    if (tx.lock_height > height) return TxResult::fail("locked");
    Amount in = 0;
    for (auto& c : coins) {
        if (c.coinbase && height < c.height + COINBASE_MATURITY) return TxResult::fail("immature-coinbase");
        in += c.out.value;
        if (in > MAX_MONEY) return TxResult::fail("inputs-overflow");
    }
    Amount out = tx.total_out();
    if (out > in) return TxResult::fail("outputs-exceed-inputs");
    if (verify_sigs) {
        std::string why;
        if (!verify_witness(tx, coins, genesis, &why)) return TxResult::fail(why);
    }
    TxResult r;
    r.fee = in - out;
    return r;
}

} // namespace quant
