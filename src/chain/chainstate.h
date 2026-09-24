// Block tree, active chain, UTXO set and on-disk storage.
//
// Disk layout (datadir/<network>/):
//   headers.dat   every accepted header (120 B each), in acceptance order
//   blocks.dat    block "core" data (header + txs without signatures), append-only
//   blockpos.dat  [hash][offset][len] index into blocks.dat
//   witness/      one file of signatures per block; deleted once PRUNE_DEPTH deep
//   undo/         spent-coin data per block for reorgs; deleted at the same depth
//   utxo.dat      UTXO snapshot + tip, rewritten periodically and on shutdown
#pragma once
#include <cstdio>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "consensus/params.h"
#include "consensus/tx_check.h"

namespace quant {

struct BlockIndex {
    Hash256 hash;
    BlockHeader header;
    int64_t height = 0;
    U256 chainwork;
    BlockIndex* prev = nullptr;
    BlockIndex* skip = nullptr;   // skip-list pointer for O(log n) ancestor lookups
    uint64_t seq = 0;             // arrival order (tie-break: first seen wins)
    std::vector<BlockIndex*> children;
    bool have_data = false;       // core data stored
    bool chain_data = false;      // this block and all ancestors have data
    bool failed = false;
    bool no_witness_ok = false;   // accepted without witness (deep, assumed valid)
    uint64_t data_pos = 0;
    uint32_t data_len = 0;
};

struct ChainStats {
    int64_t height = 0;
    int64_t header_height = 0;
    Hash256 tip;
    uint64_t utxo_count = 0;
    Amount supply = 0;
    uint64_t disk_blocks = 0, disk_witness = 0, disk_headers = 0;
    double difficulty = 0;
    uint32_t next_bits = 0;
};

class Chainstate {
public:
    Chainstate(const ChainParams& p, const std::string& datadir, bool prune = true);
    ~Chainstate();

    std::recursive_mutex mu; // "cs_main": lock before touching anything here

    bool load(std::string* err);
    void flush(); // write UTXO snapshot

    enum class HeaderResult { Ok, Known, Orphan, Invalid };
    HeaderResult accept_header(const BlockHeader& h, std::string* why, BlockIndex** out = nullptr);
    // has_witness=false is only accepted for blocks buried PRUNE_DEPTH under the best header.
    bool accept_block(const Block& b, bool has_witness, std::string* why, bool* is_new = nullptr);
    void activate_best_chain();

    const ChainParams& params() const { return p_; }
    BlockIndex* tip() const { return chain_.empty() ? nullptr : chain_.back(); }
    int64_t height() const { return int64_t(chain_.size()) - 1; }
    BlockIndex* best_header() const { return best_header_; }
    BlockIndex* lookup(const Hash256& h) const;
    BlockIndex* at_height(int64_t h) const { return h >= 0 && h < int64_t(chain_.size()) ? chain_[h] : nullptr; }
    bool in_active_chain(const BlockIndex* b) const { return b && at_height(b->height) == b; }
    std::vector<Hash256> locator(BlockIndex* from = nullptr) const;
    BlockIndex* find_fork_from_locator(const std::vector<Hash256>& loc) const;
    BlockIndex* ancestor(BlockIndex* b, int64_t height) const;
    bool is_initial_sync() const;

    uint32_t next_bits_for(const BlockIndex* prev) const;
    int64_t median_time_past(const BlockIndex* b) const;

    bool read_block(const BlockIndex* b, Block& out, bool want_witness, bool* got_witness = nullptr);
    bool have_witness(const BlockIndex* b) const;

    std::optional<Coin> get_coin(const OutPoint& o) const;
    std::vector<std::pair<OutPoint, Coin>> coins_for_address(const Hash256& addr) const;
    std::optional<Hash256> find_tx_block(const Hash256& txid) const;

    ChainStats stats() const;

    // Callbacks run with `mu` held.
    std::vector<std::function<void(const Block&, const BlockIndex*)>> on_connect;
    std::vector<std::function<void(const Block&, const BlockIndex*)>> on_disconnect;
    std::vector<std::function<void(const BlockIndex*)>> on_tip;

private:
    struct Undo { std::vector<std::pair<OutPoint, Coin>> spent; };

    BlockIndex* add_index(const BlockHeader& h);
    bool connect_block(BlockIndex* idx, std::string* why);
    bool disconnect_tip(std::string* why);
    void mark_failed(BlockIndex* b);
    void update_chain_data(BlockIndex* b);
    BlockIndex* best_candidate() const;
    bool store_block(BlockIndex* idx, const Block& b, bool has_witness);
    void prune_at(int64_t height);
    void add_coin(const OutPoint& o, const Coin& c);
    void spend_coin(const OutPoint& o);
    bool write_undo(const BlockIndex* b, const Undo& u);
    bool read_undo(const BlockIndex* b, Undo& u);
    bool load_snapshot(std::string* err);
    void index_block_txs(const Block& b, const BlockIndex* idx, bool add);
    std::string witness_path(const Hash256& h) const;
    std::string undo_path(const Hash256& h) const;

    const ChainParams& p_;
    std::string dir_;
    bool prune_;
    struct WorkCmp {
        bool operator()(const BlockIndex* a, const BlockIndex* b) const {
            int c = cmp(a->chainwork, b->chainwork);
            if (c) return c < 0;
            return a->seq > b->seq; // earlier arrival sorts higher
        }
    };
    std::set<BlockIndex*, WorkCmp> candidates_;
    uint64_t next_seq_ = 0;
    std::unordered_map<Hash256, BlockIndex*, Hash256Hasher> index_;
    std::vector<BlockIndex*> chain_;
    BlockIndex* best_header_ = nullptr;
    std::unordered_map<OutPoint, Coin, OutPointHasher> utxo_;
    std::unordered_map<Hash256, std::unordered_set<OutPoint, OutPointHasher>, Hash256Hasher> by_addr_;
    std::unordered_map<Hash256, Hash256, Hash256Hasher> txindex_; // txid -> block hash (active chain)
    Amount supply_ = 0;
    FILE* f_headers_ = nullptr;
    FILE* f_blocks_ = nullptr;
    FILE* f_blockpos_ = nullptr;
    int64_t blocks_since_flush_ = 0;
};

} // namespace quant
