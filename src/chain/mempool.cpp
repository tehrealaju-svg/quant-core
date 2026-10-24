#include "chain/mempool.h"

#include "consensus/limits.h"
#include "util/log.h"

namespace quant {

Mempool::Mempool(Chainstate& cs) : cs_(cs), view_(std::make_unique<LedgerView>(cs)) {
    cs_.on_connect.push_back([this](const Block& b, const BlockIndex*) {
        for (auto& tx : b.txs) {
            auto it = by_id_.find(tx.txid());
            if (it != by_id_.end()) { bytes_ -= it->second->size; order_.erase(it->second); by_id_.erase(it); }
        }
        dirty_ = true;
    });
    cs_.on_disconnect.push_back([this](const Block& b, const BlockIndex*) {
        // Put the block's txs back once the new chain is connected (they need their witnesses,
        // which we still have for any block recent enough to be reorganized).
        BlockIndex* idx = cs_.lookup(b.header.hash());
        Block full;
        if (idx && cs_.read_block(idx, full, true))
            for (size_t i = 1; i < full.txs.size(); i++) readd_.push_back(full.txs[i]);
        dirty_ = true;
    });
    cs_.on_tip.push_back([this](const BlockIndex*) {
        if (dirty_) rebuild();
        auto v = std::move(readd_);
        readd_.clear();
        for (auto& tx : v) { std::string why; accept(tx, &why); }
    });
}

void Mempool::rebuild() {
    dirty_ = false;
    view_ = std::make_unique<LedgerView>(cs_);
    uint64_t h = uint64_t(cs_.height() + 1);
    for (auto it = order_.begin(); it != order_.end();) {
        TxResult r = view_->apply(it->tx, h, cs_.params().genesis_hash, false); // sigs checked on entry
        if (!r.ok) {
            bytes_ -= it->size;
            by_id_.erase(it->txid);
            it = order_.erase(it);
        } else {
            it->fee = r.fee;
            ++it;
        }
    }
}

std::optional<Transaction> Mempool::get(const Hash256& txid) const {
    auto it = by_id_.find(txid);
    if (it == by_id_.end()) return std::nullopt;
    return it->second->tx;
}

std::vector<Hash256> Mempool::txids() const {
    std::vector<Hash256> v;
    for (auto& e : order_) v.push_back(e.txid);
    return v;
}

std::vector<const MempoolEntry*> Mempool::all() const {
    std::vector<const MempoolEntry*> v;
    for (auto& e : order_) v.push_back(&e);
    return v;
}

std::optional<Coin> Mempool::mempool_coin(const OutPoint& o) const {
    if (!by_id_.count(o.txid)) return std::nullopt;
    return view_->coin(o);
}

bool Mempool::accept(const Transaction& tx, std::string* why) {
    std::lock_guard lock(cs_.mu);
    auto fail = [&](const std::string& r) { if (why) *why = r; return false; };
    if (dirty_) rebuild();
    Hash256 txid = tx.txid();
    if (by_id_.count(txid)) return fail("already-in-mempool");
    if (tx.is_coinbase()) return fail("coinbase");
    TxResult basic = check_tx_basic(tx, true);
    if (!basic.ok) return fail(basic.reason);
    size_t size = tx.full_size();
    if (size > 100'000) return fail("tx-too-large");
    if (cs_.find_tx_block(txid)) return fail("already-confirmed");
    for (auto& in : tx.ins)
        if (view_->spends(in.prev)) return fail("mempool-conflict");

    // Dry run first (fee policy needs the fee before we commit into the view).
    {
        LedgerView probe(static_cast<const StateReader&>(*view_));
        TxResult r = probe.apply(tx, uint64_t(cs_.height() + 1), cs_.params().genesis_hash, true);
        if (!r.ok) return fail(r.reason);
        Amount min_fee = Amount(size) * MIN_RELAY_FEE_PER_KB / 1000;
        if (r.fee < min_fee) return fail("fee-too-low (need " + format_amount(min_fee) + ")");
        if (bytes_ + size > MAX_BYTES) return fail("mempool-full");
    }
    TxResult r = view_->apply(tx, uint64_t(cs_.height() + 1), cs_.params().genesis_hash, false);
    if (!r.ok) return fail(r.reason);

    order_.push_back(MempoolEntry{tx, txid, r.fee, size, now_seconds()});
    by_id_[txid] = std::prev(order_.end());
    bytes_ += size;
    for (auto& cb : on_added) cb(tx);
    return true;
}

std::vector<const MempoolEntry*> Mempool::select_for_block(size_t max_bytes, Amount* fees_out) const {
    // Arrival order, re-validated on a scratch view so a tx skipped for space can't leave a
    // dependent (or a trade quoted against it) invalid in the block.
    LedgerView scratch(cs_);
    uint64_t h = uint64_t(cs_.height() + 1);
    std::vector<const MempoolEntry*> out;
    size_t used = 0;
    Amount fees = 0;
    for (auto& e : order_) {
        if (used + e.size > max_bytes) continue;
        TxResult r = scratch.apply(e.tx, h, cs_.params().genesis_hash, false);
        if (!r.ok) continue;
        out.push_back(&e);
        used += e.size;
        fees += r.fee;
    }
    if (fees_out) *fees_out = fees;
    return out;
}

} // namespace quant
