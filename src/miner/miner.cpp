#include "miner/miner.h"

#include <chrono>

#include <blake3.h>

#include "consensus/limits.h"
#include "crypto/random.h"
#include "util/log.h"

namespace quant {

Block create_block_template(Chainstate& cs, Mempool& mp, const Hash256& payout, const Bytes& tag) {
    std::lock_guard lock(cs.mu);
    BlockIndex* tip = cs.tip();
    int64_t height = tip->height + 1;
    Block b;
    b.header.version = 1;
    b.header.prev = tip->hash;
    b.header.bits = cs.next_bits_for(tip);
    b.header.time = uint64_t(std::max<int64_t>(now_seconds(), cs.median_time_past(tip) + 1));

    Transaction cb;
    cb.lock_height = uint64_t(height);
    cb.extra = tag;
    if (cb.extra.size() > 60) cb.extra.resize(60);
    uint64_t en = random_u64();
    for (int i = 0; i < 8; i++) cb.extra.push_back(uint8_t(en >> (8 * i)));
    Amount fees = 0;
    auto sel = mp.select_for_block(MAX_BLOCK_SIZE - 2000, &fees);
    Amount reward = block_subsidy(uint64_t(height)) + fees;
    if (reward > 0) cb.outs.push_back(TxOut{reward, ADDR_V0, payout}); // no output once rewards end and fees are 0
    b.txs.push_back(cb);
    for (auto* e : sel) b.txs.push_back(e->tx);
    b.header.merkle_root = b.compute_merkle_root();
    b.header.witness_root = b.compute_witness_root();
    return b;
}

static inline bool hash_le_target(const uint8_t* h, const uint8_t* t) {
    return std::memcmp(h, t, 32) <= 0;
}

bool mine_header(BlockHeader& h, const ChainParams& p, uint64_t max_tries, const std::atomic<bool>* stop) {
    Hash256 target = U256::from_compact(h.bits).to_hash();
    uint8_t buf[BlockHeader::SIZE];
    h.serialize(buf);
    for (uint64_t i = 0; i < max_tries; i++) {
        if (stop && (i & 0xffff) == 0 && *stop) return false;
        uint64_t n = h.nonce + i;
        for (int k = 0; k < 8; k++) buf[BlockHeader::SIZE - 8 + k] = uint8_t(n >> (8 * k));
        uint8_t out[32];
        blake3_hasher hs;
        blake3_hasher_init(&hs);
        blake3_hasher_update(&hs, buf, sizeof buf);
        blake3_hasher_finalize(&hs, out, 32);
        if (hash_le_target(out, target.data())) { h.nonce = n; return true; }
    }
    return false;
}

Miner::Miner(Chainstate& cs, Mempool& mp) : cs_(cs), mp_(mp) {}
Miner::~Miner() { stop(); }

void Miner::start(int threads, const Hash256& payout) {
    stop();
    if (threads <= 0) return;
    {
        std::lock_guard l(tmpl_mu_);
        payout_ = payout;
    }
    running_ = true;
    dirty_ = true;
    nthreads_ = threads;
    coord_ = std::thread([this] { coordinator(); });
    for (int i = 0; i < threads; i++) workers_.emplace_back([this, i] { worker(i); });
    logf("miner started with %d threads", threads);
}

void Miner::stop() {
    if (!running_) return;
    running_ = false;
    if (coord_.joinable()) coord_.join();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
    nthreads_ = 0;
    hashrate_ = 0;
    logf("miner stopped");
}

void Miner::coordinator() {
    auto last_build = std::chrono::steady_clock::now() - std::chrono::hours(1);
    auto last_rate = std::chrono::steady_clock::now();
    uint64_t last_hashes = hashes_;
    while (running_) {
        auto now = std::chrono::steady_clock::now();
        if (dirty_ || now - last_build > std::chrono::seconds(20)) {
            dirty_ = false;
            Hash256 pay;
            { std::lock_guard l(tmpl_mu_); pay = payout_; }
            Block b = create_block_template(cs_, mp_, pay, tag);
            {
                std::lock_guard l(tmpl_mu_);
                tmpl_ = std::move(b);
                target_ = U256::from_compact(tmpl_.header.bits).to_hash();
            }
            tmpl_version_++;
            last_build = now;
        }
        if (now - last_rate >= std::chrono::seconds(2)) {
            uint64_t h = hashes_;
            double secs = std::chrono::duration<double>(now - last_rate).count();
            hashrate_ = double(h - last_hashes) / secs;
            last_hashes = h;
            last_rate = now;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Miner::worker(int id) {
    uint64_t seen = 0;
    BlockHeader hdr;
    Hash256 target;
    uint8_t buf[BlockHeader::SIZE];
    uint64_t nonce = 0;
    while (running_) {
        if (tmpl_version_ != seen || seen == 0) {
            while (running_ && tmpl_version_ == 0) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            std::lock_guard l(tmpl_mu_);
            seen = tmpl_version_;
            hdr = tmpl_.header;
            target = target_;
            hdr.serialize(buf);
            nonce = random_u64();
        }
        constexpr int BATCH = 4096;
        for (int i = 0; i < BATCH; i++, nonce++) {
            for (int k = 0; k < 8; k++) buf[BlockHeader::SIZE - 8 + k] = uint8_t(nonce >> (8 * k));
            uint8_t out[32];
            blake3_hasher hs;
            blake3_hasher_init(&hs);
            blake3_hasher_update(&hs, buf, sizeof buf);
            blake3_hasher_finalize(&hs, out, 32);
            if (hash_le_target(out, target.data())) {
                Block found;
                {
                    std::lock_guard l(tmpl_mu_);
                    if (tmpl_version_ != seen) break; // stale
                    found = tmpl_;
                }
                found.header.nonce = nonce;
                found_++;
                dirty_ = true;
                logf("miner: found block at height %llu (%s)", (unsigned long long)found.txs[0].lock_height,
                     found.header.hash().hex().substr(0, 16).c_str());
                if (on_found) on_found(found);
                // Wait for the coordinator to build a template on top of the new block.
                while (running_ && tmpl_version_ == seen) std::this_thread::sleep_for(std::chrono::milliseconds(5));
                break;
            }
        }
        hashes_ += BATCH;
    }
    (void)id;
}

} // namespace quant
