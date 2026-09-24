// Unconfirmed transactions waiting for a block. Guarded by Chainstate::mu.
#pragma once
#include <map>
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
    bool contains(const Hash256& txid) const { return entries_.count(txid) != 0; }
    std::optional<Transaction> get(const Hash256& txid) const;
    std::vector<Hash256> txids() const;
    size_t size() const { return entries_.size(); }
    size_t bytes() const { return bytes_; }
    // Is this outpoint spent by something in the mempool?
    bool spends(const OutPoint& o) const { return spent_by_.count(o) != 0; }
    // Outputs created by mempool txs (for chained unconfirmed spends).
    std::optional<Coin> mempool_coin(const OutPoint& o) const;

    // Highest-feerate txs (dependency ordered) that fit in max_bytes.
    std::vector<const MempoolEntry*> select_for_block(size_t max_bytes, Amount* fees_out) const;
    std::vector<const MempoolEntry*> all() const;

    std::vector<std::function<void(const Transaction&)>> on_added;

private:
    void remove(const Hash256& txid, bool recursive);
    void block_connected(const Block& b);
    void block_disconnected(const Block& b);

    Chainstate& cs_;
    std::unordered_map<Hash256, MempoolEntry, Hash256Hasher> entries_;
    std::unordered_map<OutPoint, Hash256, OutPointHasher> spent_by_;
    size_t bytes_ = 0;
    std::vector<Transaction> readd_;
    static constexpr size_t MAX_BYTES = 64 * 1024 * 1024;
};

} // namespace quant
