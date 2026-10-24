// Unconfirmed transactions waiting for a block. Guarded by Chainstate::mu.
//
// Transactions are kept in arrival order and applied, in that order, to a LedgerView over the
// chain — so pool trades see the reserves left by earlier pending trades, and every quote a
// wallet gets from the mempool view is what the next block will actually execute.
#pragma once
#include <list>
#include <memory>
#include <unordered_map>

#include "chain/chainstate.h"

namespace quant {

struct MempoolEntry {
    Transaction tx;
    Hash256 txid;
    Amount fee = 0;
    size_t size = 0;
    int64_t time = 0;
    double feerate() const { return size ? double(fee) / double(size) : 0; }
};

class Mempool {
public:
    explicit Mempool(Chainstate& cs);

    // Validates and adds. Returns false with a reason on rejection.
    bool accept(const Transaction& tx, std::string* why);
    bool contains(const Hash256& txid) const { return by_id_.count(txid) != 0; }
    std::optional<Transaction> get(const Hash256& txid) const;
    std::vector<Hash256> txids() const;
    size_t size() const { return order_.size(); }
    size_t bytes() const { return bytes_; }
    bool spends(const OutPoint& o) const { return view_->spends(o); }
    // Coins created by pending txs (for chained unconfirmed spends).
    std::optional<Coin> mempool_coin(const OutPoint& o) const;
    // Chain state with every pending tx applied (pool reserves, new tokens, coins).
    const StateReader& view() const { return *view_; }

    // Pending txs in arrival order that fit in max_bytes (all valid when applied in this order).
    std::vector<const MempoolEntry*> select_for_block(size_t max_bytes, Amount* fees_out) const;
    std::vector<const MempoolEntry*> all() const;

    std::vector<std::function<void(const Transaction&)>> on_added;

private:
    void rebuild(); // re-apply all entries to a fresh view, dropping the ones that became invalid

    Chainstate& cs_;
    std::list<MempoolEntry> order_;
    std::unordered_map<Hash256, std::list<MempoolEntry>::iterator, Hash256Hasher> by_id_;
    std::unique_ptr<LedgerView> view_;
    size_t bytes_ = 0;
    std::vector<Transaction> readd_;
    bool dirty_ = false;
    static constexpr size_t MAX_BYTES = 64 * 1024 * 1024;
};

} // namespace quant
