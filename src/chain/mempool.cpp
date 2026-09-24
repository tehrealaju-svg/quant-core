#include "chain/mempool.h"

#include <algorithm>
#include <set>

#include "consensus/limits.h"
#include "util/log.h"

namespace quant {

Mempool::Mempool(Chainstate& cs) : cs_(cs) {
    cs_.on_connect.push_back([this](const Block& b, const BlockIndex*) { block_connected(b); });
    cs_.on_disconnect.push_back([this](const Block& b, const BlockIndex*) { block_disconnected(b); });
    // Re-validate reorged-out txs once the new chain is fully connected.
    cs_.on_tip.push_back([this](const BlockIndex*) {
        auto v = std::move(readd_);
        readd_.clear();
        for (auto& tx : v) { std::string why; accept(tx, &why); }
    });
}

std::optional<Transaction> Mempool::get(const Hash256& txid) const {
    auto it = entries_.find(txid);
    if (it == entries_.end()) return std::nullopt;
    return it->second.tx;
}

std::vector<Hash256> Mempool::txids() const {
    std::vector<Hash256> v;
    for (auto& [h, e] : entries_) v.push_back(h);
    return v;
}

std::vector<const MempoolEntry*> Mempool::all() const {
    std::vector<const MempoolEntry*> v;
    for (auto& [h, e] : entries_) v.push_back(&e);
    return v;
}

std::optional<Coin> Mempool::mempool_coin(const OutPoint& o) const {
    auto it = entries_.find(o.txid);
    if (it == entries_.end() || o.n >= it->second.tx.outs.size()) return std::nullopt;
    return Coin{it->second.tx.outs[o.n], uint64_t(cs_.height() + 1), false};
}

bool Mempool::accept(const Transaction& tx, std::string* why) {
    std::lock_guard lock(cs_.mu);
    auto fail = [&](const std::string& r) { if (why) *why = r; return false; };
    Hash256 txid = tx.txid();
    if (entries_.count(txid)) return fail("already-in-mempool");
    if (tx.is_coinbase()) return fail("coinbase");
    TxResult basic = check_tx_basic(tx, true);
    if (!basic.ok) return fail(basic.reason);
    size_t size = tx.full_size();
    if (size > 100'000) return fail("tx-too-large");
    if (cs_.find_tx_block(txid)) return fail("already-confirmed");

    std::vector<Coin> coins;
    for (auto& in : tx.ins) {
        if (spent_by_.count(in.prev)) return fail("mempool-conflict");
        auto c = cs_.get_coin(in.prev);
        if (!c) c = mempool_coin(in.prev);
        if (!c) return fail("missing-inputs");
        coins.push_back(*c);
    }
    TxResult r = check_tx_inputs(tx, coins, uint64_t(cs_.height() + 1), cs_.params().genesis_hash, true);
    if (!r.ok) return fail(r.reason);
    Amount min_fee = Amount(size) * MIN_RELAY_FEE_PER_KB / 1000;
    if (r.fee < min_fee) return fail("fee-too-low (need " + format_amount(min_fee) + ")");

    // Evict the cheapest txs if full (never evict for a cheaper one).
    while (bytes_ + size > MAX_BYTES && !entries_.empty()) {
        auto worst = std::min_element(entries_.begin(), entries_.end(),
                                      [](auto& a, auto& b) { return a.second.feerate() < b.second.feerate(); });
        if (worst->second.feerate() >= double(r.fee) / double(size)) return fail("mempool-full");
        remove(worst->first, true);
    }

    MempoolEntry e{tx, txid, r.fee, size, now_seconds()};
    for (auto& in : tx.ins) spent_by_[in.prev] = txid;
    bytes_ += size;
    entries_.emplace(txid, std::move(e));
    for (auto& cb : on_added) cb(tx);
    return true;
}

void Mempool::remove(const Hash256& txid, bool recursive) {
    auto it = entries_.find(txid);
    if (it == entries_.end()) return;
    Transaction tx = it->second.tx;
    for (auto& in : tx.ins) spent_by_.erase(in.prev);
    bytes_ -= it->second.size;
    entries_.erase(it);
    if (recursive) {
        for (uint32_t n = 0; n < tx.outs.size(); n++) {
            auto s = spent_by_.find(OutPoint{txid, n});
            if (s != spent_by_.end()) remove(s->second, true);
        }
    }
}

void Mempool::block_connected(const Block& b) {
    for (auto& tx : b.txs) {
        Hash256 id = tx.txid();
        if (entries_.count(id)) { remove(id, false); continue; }
        // Anything else spending the same inputs is now a double spend.
        for (auto& in : tx.ins) {
            auto s = spent_by_.find(in.prev);
            if (s != spent_by_.end()) remove(s->second, true);
        }
    }
}

void Mempool::block_disconnected(const Block& b) {
    // Put the block's transactions back (best effort; they need their witnesses, which
    // we still have for any block recent enough to be reorganized).
    BlockIndex* idx = cs_.lookup(b.header.hash());
    Block full;
    if (!idx || !cs_.read_block(idx, full, true)) return;
    for (size_t i = 1; i < full.txs.size(); i++) readd_.push_back(full.txs[i]);
}

std::vector<const MempoolEntry*> Mempool::select_for_block(size_t max_bytes, Amount* fees_out) const {
    std::vector<const MempoolEntry*> sorted;
    for (auto& [h, e] : entries_) sorted.push_back(&e);
    std::sort(sorted.begin(), sorted.end(), [](auto* a, auto* b) { return a->feerate() > b->feerate(); });
    std::vector<const MempoolEntry*> out;
    std::unordered_set<Hash256, Hash256Hasher> included;
    size_t used = 0;
    Amount fees = 0;
    // Repeated passes so children land after their parents.
    bool progress = true;
    while (progress) {
        progress = false;
        for (auto* e : sorted) {
            if (included.count(e->txid) || used + e->size > max_bytes) continue;
            bool ready = true;
            for (auto& in : e->tx.ins)
                if (entries_.count(in.prev.txid) && !included.count(in.prev.txid)) { ready = false; break; }
            if (!ready) continue;
            out.push_back(e);
            included.insert(e->txid);
            used += e->size;
            fees += e->fee;
            progress = true;
        }
    }
    if (fees_out) *fees_out = fees;
    return out;
}

} // namespace quant
