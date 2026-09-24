// Multi-threaded BLAKE3 proof-of-work miner.
#pragma once
#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

#include "chain/mempool.h"

namespace quant {

// Build a block template paying `payout` (subsidy + fees) on top of the current tip.
Block create_block_template(Chainstate& cs, Mempool& mp, const Hash256& payout, const Bytes& tag);
// Grind nonces on the calling thread until found or `max_tries` exhausted.
bool mine_header(BlockHeader& h, const ChainParams& p, uint64_t max_tries, const std::atomic<bool>* stop = nullptr);

class Miner {
public:
    Miner(Chainstate& cs, Mempool& mp);
    ~Miner();

    void start(int threads, const Hash256& payout);
    void stop();
    bool running() const { return running_; }
    int threads() const { return nthreads_; }
    double hashrate() const { return hashrate_; }
    uint64_t blocks_found() const { return found_; }
    Hash256 payout() const { std::lock_guard l(tmpl_mu_); return payout_; }
    void notify_new_tip() { dirty_ = true; }

    std::function<void(const Block&)> on_found; // called from a miner thread
    Bytes tag = {'Q', 'u', 'a', 'n', 't'};

private:
    void coordinator();
    void worker(int id);

    Chainstate& cs_;
    Mempool& mp_;
    std::atomic<bool> running_{false}, dirty_{true};
    std::atomic<int> nthreads_{0};
    std::atomic<uint64_t> found_{0}, hashes_{0};
    std::atomic<double> hashrate_{0};
    std::atomic<uint64_t> tmpl_version_{0};
    mutable std::mutex tmpl_mu_;
    Block tmpl_;
    Hash256 target_;
    Hash256 payout_;
    std::thread coord_;
    std::vector<std::thread> workers_;
};

} // namespace quant
