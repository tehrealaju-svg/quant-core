#include "chain/chainstate.h"

#include <algorithm>
#include <filesystem>
#include <set>

#include "consensus/limits.h"
#include "consensus/pow.h"
#include "crypto/hash.h"
#include "util/log.h"

namespace fs = std::filesystem;

namespace quant {

// ---------------------------------------------------------------- file helpers
static bool fseek64(FILE* f, uint64_t pos) {
#ifdef _WIN32
    return _fseeki64(f, int64_t(pos), SEEK_SET) == 0;
#else
    return fseeko(f, off_t(pos), SEEK_SET) == 0;
#endif
}
static uint64_t fsize64(FILE* f) {
#ifdef _WIN32
    _fseeki64(f, 0, SEEK_END);
    return uint64_t(_ftelli64(f));
#else
    fseeko(f, 0, SEEK_END);
    return uint64_t(ftello(f));
#endif
}
static bool read_file(const std::string& path, Bytes& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint64_t n = fsize64(f);
    fseek64(f, 0);
    out.resize(n);
    bool ok = n == 0 || fread(out.data(), 1, n, f) == n;
    fclose(f);
    return ok;
}
static bool write_file_atomic(const std::string& path, const Bytes& data) {
    std::string tmp = path + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f) return false;
    bool ok = data.empty() || fwrite(data.data(), 1, data.size(), f) == data.size();
    ok = fflush(f) == 0 && ok;
    fclose(f);
    if (!ok) return false;
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

static void write_coin(Writer& w, const Coin& c) {
    w.varint(c.out.value); w.u8(c.out.addr_ver); w.hash(c.out.addr);
    w.varint(c.height); w.u8(c.coinbase ? 1 : 0);
}
static Coin read_coin(Reader& r) {
    Coin c;
    c.out.value = r.varint(); c.out.addr_ver = r.u8(); c.out.addr = r.hash();
    c.height = r.varint(); c.coinbase = r.u8() != 0;
    return c;
}

// ---------------------------------------------------------------- skip list (O(log n) ancestors)
static int64_t invert_lowest_one(int64_t n) { return n & (n - 1); }
static int64_t skip_height(int64_t h) {
    if (h < 2) return 0;
    return (h & 1) ? invert_lowest_one(invert_lowest_one(h - 1)) + 1 : invert_lowest_one(h);
}
BlockIndex* Chainstate::ancestor(BlockIndex* b, int64_t height) const {
    if (!b || height > b->height || height < 0) return nullptr;
    if (in_active_chain(b)) return chain_[height];
    BlockIndex* walk = b;
    int64_t hw = b->height;
    while (hw > height) {
        BlockIndex* sk = walk->skip;
        int64_t hs = skip_height(hw), hsp = skip_height(hw - 1);
        if (sk && (hs == height || (hs > height && !(hsp < hs - 2 && hsp >= height)))) { walk = sk; hw = hs; }
        else { walk = walk->prev; hw--; }
    }
    return walk;
}

// ---------------------------------------------------------------- construction / loading
Chainstate::Chainstate(const ChainParams& p, const std::string& datadir, bool prune)
    : p_(p), dir_(datadir), prune_(prune) {}

Chainstate::~Chainstate() {
    if (f_headers_) fclose(f_headers_);
    if (f_blocks_) fclose(f_blocks_);
    if (f_blockpos_) fclose(f_blockpos_);
    for (auto& [h, b] : index_) delete b;
}

std::string Chainstate::witness_path(const Hash256& h) const { return dir_ + "/witness/" + h.hex() + ".w"; }
std::string Chainstate::undo_path(const Hash256& h) const { return dir_ + "/undo/" + h.hex() + ".u"; }

BlockIndex* Chainstate::lookup(const Hash256& h) const {
    auto it = index_.find(h);
    return it == index_.end() ? nullptr : it->second;
}

BlockIndex* Chainstate::add_index(const BlockHeader& h) {
    auto* b = new BlockIndex;
    b->hash = h.hash();
    b->header = h;
    b->prev = lookup(h.prev);
    b->height = b->prev ? b->prev->height + 1 : 0;
    b->chainwork = (b->prev ? b->prev->chainwork : U256()) + work_from_target(U256::from_compact(h.bits));
    b->seq = next_seq_++;
    if (b->prev) {
        b->prev->children.push_back(b);
        b->skip = ancestor(b->prev, skip_height(b->height));
    }
    index_[b->hash] = b;
    if (!best_header_ || (b->chainwork > best_header_->chainwork && !b->failed)) best_header_ = b;
    return b;
}

bool Chainstate::load(std::string* err) {
    std::lock_guard lock(mu);
    std::error_code ec;
    fs::create_directories(dir_ + "/witness", ec);
    fs::create_directories(dir_ + "/undo", ec);

    // headers
    Bytes hb;
    read_file(dir_ + "/headers.dat", hb);
    size_t nh = hb.size() / BlockHeader::SIZE;
    if (hb.size() % BlockHeader::SIZE) {
        logf("headers.dat: truncating partial record");
        hb.resize(nh * BlockHeader::SIZE);
        write_file_atomic(dir_ + "/headers.dat", hb);
    }
    f_headers_ = fopen((dir_ + "/headers.dat").c_str(), "ab");
    if (!f_headers_) { if (err) *err = "cannot open headers.dat in " + dir_; return false; }
    for (size_t i = 0; i < nh; i++) {
        Reader r(hb.data() + i * BlockHeader::SIZE, BlockHeader::SIZE);
        BlockHeader h = BlockHeader::read(r);
        if (i == 0) {
            if (h.hash() != p_.genesis_hash) { if (err) *err = "headers.dat belongs to a different network/genesis"; return false; }
        } else if (!lookup(h.prev)) {
            continue; // orphaned record (should not happen)
        }
        if (!lookup(h.hash())) add_index(h);
    }
    if (index_.empty()) {
        add_index(p_.genesis.header);
        uint8_t raw[BlockHeader::SIZE];
        p_.genesis.header.serialize(raw);
        fwrite(raw, 1, sizeof raw, f_headers_);
        fflush(f_headers_);
    }

    // block data positions
    f_blocks_ = fopen((dir_ + "/blocks.dat").c_str(), "a+b");
    f_blockpos_ = fopen((dir_ + "/blockpos.dat").c_str(), "ab");
    if (!f_blocks_ || !f_blockpos_) { if (err) *err = "cannot open blocks.dat"; return false; }
    uint64_t blocks_size = fsize64(f_blocks_);
    Bytes pb;
    read_file(dir_ + "/blockpos.dat", pb);
    for (size_t i = 0; i + 44 <= pb.size(); i += 44) {
        Reader r(pb.data() + i, 44);
        Hash256 h = r.hash();
        uint64_t pos = r.u64le();
        uint32_t len = r.u32le();
        if (pos + len > blocks_size) continue;
        if (auto* b = lookup(h)) { b->have_data = true; b->data_pos = pos; b->data_len = len; }
    }
    BlockIndex* g = lookup(p_.genesis_hash);
    if (!g->have_data) store_block(g, p_.genesis, true);

    // chain_data flags in height order
    std::vector<BlockIndex*> all;
    for (auto& [h, b] : index_) all.push_back(b);
    std::sort(all.begin(), all.end(), [](auto* a, auto* b) { return a->height < b->height; });
    for (auto* b : all) {
        b->chain_data = b->have_data && (!b->prev || b->prev->chain_data);
        if (b->chain_data) candidates_.insert(b);
    }

    if (!load_snapshot(err)) return false;

    // tx index for the explorer: scan the active chain's core data.
    for (auto* b : chain_) {
        Block blk;
        if (read_block(b, blk, false)) index_block_txs(blk, b, true);
    }
    logf("loaded %zu headers, chain height %lld, best header %lld, %zu utxos",
         index_.size(), (long long)height(), (long long)best_header_->height, utxo_.size());
    activate_best_chain();
    return true;
}

bool Chainstate::load_snapshot(std::string* err) {
    Bytes sb;
    BlockIndex* g = lookup(p_.genesis_hash);
    chain_.clear();
    if (!read_file(dir_ + "/utxo.dat", sb) || sb.size() < 4 + 32 + 32) {
        chain_.push_back(g);
        return true;
    }
    try {
        Hash256 check = blake3(sb.data(), sb.size() - 32);
        if (std::memcmp(check.data(), sb.data() + sb.size() - 32, 32) != 0) throw SerializeError("checksum");
        Reader r(sb.data(), sb.size() - 32);
        if (r.u32le() != 0x58545551) throw SerializeError("magic"); // "QUTX"
        Hash256 tiph = r.hash();
        uint64_t n = r.varint();
        BlockIndex* t = lookup(tiph);
        if (!t || !t->chain_data) throw SerializeError("snapshot tip unknown");
        for (uint64_t i = 0; i < n; i++) {
            OutPoint o;
            o.txid = r.hash();
            o.n = uint32_t(r.varint());
            add_coin(o, read_coin(r));
        }
        chain_.resize(t->height + 1);
        for (BlockIndex* w = t; w; w = w->prev) chain_[w->height] = w;
    } catch (const std::exception& e) {
        logf("utxo.dat unusable (%s) - rebuilding from blocks", e.what());
        utxo_.clear(); by_addr_.clear(); supply_ = 0;
        chain_.assign(1, g);
    }
    return true;
}

void Chainstate::flush() {
    std::lock_guard lock(mu);
    Writer w;
    w.u32le(0x58545551);
    w.hash(tip()->hash);
    w.varint(utxo_.size());
    for (auto& [o, c] : utxo_) { w.hash(o.txid); w.varint(o.n); write_coin(w, c); }
    Hash256 check = blake3(w.buf);
    w.hash(check);
    if (!write_file_atomic(dir_ + "/utxo.dat", w.buf)) logf("WARNING: failed to write utxo.dat");
    blocks_since_flush_ = 0;
}

// ---------------------------------------------------------------- queries
std::vector<Hash256> Chainstate::locator(BlockIndex* from) const {
    std::vector<Hash256> v;
    if (!from) from = tip();
    int64_t step = 1;
    for (BlockIndex* b = from; b;) {
        v.push_back(b->hash);
        if (b->height == 0) break;
        int64_t h = std::max<int64_t>(b->height - step, 0);
        b = ancestor(b, h);
        if (v.size() > 10) step *= 2;
    }
    return v;
}

BlockIndex* Chainstate::find_fork_from_locator(const std::vector<Hash256>& loc) const {
    for (auto& h : loc) {
        BlockIndex* b = lookup(h);
        if (b && in_active_chain(b)) return b;
    }
    return chain_.empty() ? nullptr : chain_[0];
}

bool Chainstate::is_initial_sync() const {
    if (!tip() || !best_header_) return true;
    if (best_header_->height > tip()->height + 10) return true;
    return int64_t(tip()->header.time) < now_seconds() - 24 * 3600;
}

int64_t Chainstate::median_time_past(const BlockIndex* b) const {
    std::vector<int64_t> t;
    for (int i = 0; i < MEDIAN_TIME_SPAN && b; i++, b = b->prev) t.push_back(int64_t(b->header.time));
    std::sort(t.begin(), t.end());
    return t.empty() ? 0 : t[t.size() / 2];
}

uint32_t Chainstate::next_bits_for(const BlockIndex* prev) const {
    std::vector<const BlockIndex*> back;
    const BlockIndex* w = prev;
    for (int i = 0; i <= LWMA_WINDOW + 1 && w; i++, w = w->prev) back.push_back(w);
    return next_bits(prev->height, [&](int i) { return HeaderInfo{back[i]->header.time, back[i]->header.bits}; }, p_);
}

bool Chainstate::have_witness(const BlockIndex* b) const {
    std::error_code ec;
    return fs::exists(witness_path(b->hash), ec);
}

bool Chainstate::read_block(const BlockIndex* b, Block& out, bool want_witness, bool* got_witness) {
    if (got_witness) *got_witness = false;
    if (!b->have_data) return false;
    Bytes buf(b->data_len);
    fflush(f_blocks_);
    if (!fseek64(f_blocks_, b->data_pos) || fread(buf.data(), 1, buf.size(), f_blocks_) != buf.size()) return false;
    try {
        Reader r(buf);
        out = Block::read_core(r);
        if (out.header.hash() != b->hash) return false;
        if (want_witness) {
            Bytes wb;
            if (read_file(witness_path(b->hash), wb)) {
                Reader wr(wb);
                out.read_witness(wr);
                if (got_witness) *got_witness = true;
            }
        }
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

std::optional<Coin> Chainstate::get_coin(const OutPoint& o) const {
    auto it = utxo_.find(o);
    if (it == utxo_.end()) return std::nullopt;
    return it->second;
}

std::vector<std::pair<OutPoint, Coin>> Chainstate::coins_for_address(const Hash256& addr) const {
    std::vector<std::pair<OutPoint, Coin>> v;
    auto it = by_addr_.find(addr);
    if (it == by_addr_.end()) return v;
    for (auto& o : it->second) v.push_back({o, utxo_.at(o)});
    return v;
}

std::optional<Hash256> Chainstate::find_tx_block(const Hash256& txid) const {
    auto it = txindex_.find(txid);
    if (it == txindex_.end()) return std::nullopt;
    return it->second;
}

ChainStats Chainstate::stats() const {
    ChainStats s;
    s.height = height();
    s.header_height = best_header_ ? best_header_->height : 0;
    s.tip = tip()->hash;
    s.utxo_count = utxo_.size();
    s.supply = supply_;
    std::error_code ec;
    s.disk_blocks = fs::file_size(dir_ + "/blocks.dat", ec);
    s.disk_headers = fs::file_size(dir_ + "/headers.dat", ec);
    for (auto& e : fs::directory_iterator(dir_ + "/witness", ec)) s.disk_witness += e.file_size(ec);
    U256 lim = p_.pow_limit;
    U256 cur = U256::from_compact(tip()->header.bits);
    s.difficulty = cur.is_zero() ? 0 : lim.to_double() / cur.to_double();
    s.next_bits = next_bits_for(tip());
    return s;
}

// ---------------------------------------------------------------- UTXO helpers
void Chainstate::add_coin(const OutPoint& o, const Coin& c) {
    utxo_[o] = c;
    by_addr_[c.out.addr].insert(o);
    supply_ += c.out.value;
}

void Chainstate::spend_coin(const OutPoint& o) {
    auto it = utxo_.find(o);
    if (it == utxo_.end()) return;
    auto a = by_addr_.find(it->second.out.addr);
    if (a != by_addr_.end()) { a->second.erase(o); if (a->second.empty()) by_addr_.erase(a); }
    supply_ -= it->second.out.value;
    utxo_.erase(it);
}

void Chainstate::index_block_txs(const Block& b, const BlockIndex* idx, bool add) {
    for (auto& t : b.txs) {
        if (add) txindex_[t.txid()] = idx->hash;
        else txindex_.erase(t.txid());
    }
}

// ---------------------------------------------------------------- headers
Chainstate::HeaderResult Chainstate::accept_header(const BlockHeader& h, std::string* why, BlockIndex** out) {
    std::lock_guard lock(mu);
    auto fail = [&](const char* r) { if (why) *why = r; return HeaderResult::Invalid; };
    Hash256 hash = h.hash();
    if (BlockIndex* b = lookup(hash)) {
        if (out) *out = b;
        return b->failed ? fail("known-invalid") : HeaderResult::Known;
    }
    BlockIndex* prev = lookup(h.prev);
    if (!prev) { if (why) *why = "orphan"; return HeaderResult::Orphan; }
    if (prev->failed) return fail("prev-invalid");
    if (h.version < 1) return fail("bad-version");
    if (!check_pow(hash, h.bits, p_)) return fail("high-hash");
    if (h.bits != next_bits_for(prev)) return fail("bad-difficulty-bits");
    if (int64_t(h.time) <= median_time_past(prev)) return fail("time-too-old");
    if (int64_t(h.time) > now_seconds() + MAX_FUTURE_DRIFT) return fail("time-too-new");
    // Refuse forks deeper than our undo data reaches (also a long-range-attack guard).
    BlockIndex* t = tip();
    BlockIndex* a = ancestor(prev, std::min(prev->height, t->height));
    while (a && !in_active_chain(a)) a = a->prev;
    if (a && t->height - a->height > MAX_REORG_DEPTH) return fail("fork-too-deep");

    BlockIndex* b = add_index(h);
    uint8_t raw[BlockHeader::SIZE];
    h.serialize(raw);
    fwrite(raw, 1, sizeof raw, f_headers_);
    fflush(f_headers_);
    if (out) *out = b;
    return HeaderResult::Ok;
}

// ---------------------------------------------------------------- blocks
bool Chainstate::store_block(BlockIndex* idx, const Block& b, bool has_witness) {
    Bytes core = b.core_bytes();
    uint64_t pos = fsize64(f_blocks_);
    if (fwrite(core.data(), 1, core.size(), f_blocks_) != core.size()) return false;
    fflush(f_blocks_);
    Writer w;
    w.hash(idx->hash); w.u64le(pos); w.u32le(uint32_t(core.size()));
    fwrite(w.buf.data(), 1, w.buf.size(), f_blockpos_);
    fflush(f_blockpos_);
    idx->data_pos = pos;
    idx->data_len = uint32_t(core.size());
    idx->have_data = true;
    if (has_witness) {
        bool keep = !prune_ || !best_header_ || idx->height + PRUNE_DEPTH > best_header_->height;
        if (keep) write_file_atomic(witness_path(idx->hash), b.witness_bytes());
    }
    return true;
}

void Chainstate::update_chain_data(BlockIndex* b) {
    if (!b->have_data || (b->prev && !b->prev->chain_data)) return;
    std::vector<BlockIndex*> todo{b};
    while (!todo.empty()) {
        BlockIndex* x = todo.back();
        todo.pop_back();
        if (!x->have_data || x->chain_data) continue;
        x->chain_data = true;
        if (!x->failed) candidates_.insert(x);
        for (auto* c : x->children) todo.push_back(c);
    }
}

bool Chainstate::accept_block(const Block& b, bool has_witness, std::string* why, bool* is_new) {
    std::lock_guard lock(mu);
    if (is_new) *is_new = false;
    auto fail = [&](const std::string& r) { if (why) *why = r; return false; };
    BlockIndex* idx = nullptr;
    auto hr = accept_header(b.header, why, &idx);
    if (hr == HeaderResult::Invalid || hr == HeaderResult::Orphan) return false;
    if (idx->have_data) {
        // Already stored. Fill in a missing witness if we can still use it.
        if (has_witness && !have_witness(idx) && !in_active_chain(idx) &&
            b.compute_witness_root() == b.header.witness_root) {
            write_file_atomic(witness_path(idx->hash), b.witness_bytes());
            activate_best_chain();
        }
        return true;
    }

    if (b.txs.empty() || !b.txs[0].is_coinbase()) return fail("no-coinbase");
    for (size_t i = 1; i < b.txs.size(); i++) if (b.txs[i].is_coinbase()) return fail("extra-coinbase");
    if (b.compute_merkle_root() != b.header.merkle_root) return fail("bad-merkle-root");
    if (has_witness) {
        if (b.compute_witness_root() != b.header.witness_root) return fail("bad-witness-root");
        if (b.full_size() > MAX_BLOCK_SIZE) return fail("block-too-big");
    } else {
        if (b.core_bytes().size() > MAX_BLOCK_SIZE) return fail("block-too-big");
        if (!best_header_ || idx->height + PRUNE_DEPTH > best_header_->height) return fail("witness-required");
        idx->no_witness_ok = true;
    }
    if (b.txs[0].lock_height != uint64_t(idx->height)) return fail("bad-coinbase-height");
    std::unordered_set<Hash256, Hash256Hasher> ids;
    for (auto& t : b.txs) {
        TxResult r = check_tx_basic(t, has_witness);
        if (!r.ok) return fail("tx " + t.txid().hex().substr(0, 16) + ": " + r.reason);
        if (!ids.insert(t.txid()).second) return fail("duplicate-tx");
    }
    if (!store_block(idx, b, has_witness)) return fail("disk-write-failed");
    if (is_new) *is_new = true;
    update_chain_data(idx);
    activate_best_chain();
    return true;
}

BlockIndex* Chainstate::best_candidate() const {
    for (auto it = candidates_.rbegin(); it != candidates_.rend(); ++it)
        if (!(*it)->failed) return (*it)->chainwork > tip()->chainwork ? *it : tip();
    return tip();
}

void Chainstate::mark_failed(BlockIndex* b) {
    std::vector<BlockIndex*> todo{b};
    while (!todo.empty()) {
        BlockIndex* x = todo.back();
        todo.pop_back();
        x->failed = true;
        candidates_.erase(x);
        for (auto* c : x->children) todo.push_back(c);
    }
    best_header_ = lookup(p_.genesis_hash);
    for (auto& [h, i] : index_)
        if (!i->failed && i->chainwork > best_header_->chainwork) best_header_ = i;
}

bool Chainstate::write_undo(const BlockIndex* b, const Undo& u) {
    Writer w;
    w.varint(u.spent.size());
    for (auto& [o, c] : u.spent) { w.hash(o.txid); w.varint(o.n); write_coin(w, c); }
    return write_file_atomic(undo_path(b->hash), w.buf);
}

bool Chainstate::read_undo(const BlockIndex* b, Undo& u) {
    Bytes buf;
    if (!read_file(undo_path(b->hash), buf)) return false;
    try {
        Reader r(buf);
        uint64_t n = r.varint();
        for (uint64_t i = 0; i < n; i++) {
            OutPoint o; o.txid = r.hash(); o.n = uint32_t(r.varint());
            u.spent.push_back({o, read_coin(r)});
        }
    } catch (...) { return false; }
    return true;
}

enum ConnectResult { CONNECT_OK, CONNECT_INVALID, CONNECT_MISSING };

bool Chainstate::connect_block(BlockIndex* idx, std::string* why) {
    Block b;
    bool got_witness = false;
    if (!read_block(idx, b, true, &got_witness)) { if (why) *why = "read-failed"; return false; }
    bool deep = best_header_ && idx->height + PRUNE_DEPTH <= best_header_->height;
    if (!got_witness && !deep && idx->height > 0) { if (why) *why = "missing-witness"; return false; }
    bool verify = got_witness && idx->height > 0;
    const uint64_t height = uint64_t(idx->height);

    // Scratch view so a bad tx leaves the UTXO set untouched.
    std::unordered_map<OutPoint, Coin, OutPointHasher> created;
    std::unordered_set<OutPoint, OutPointHasher> spent;
    Undo undo;
    auto find = [&](const OutPoint& o) -> std::optional<Coin> {
        if (spent.count(o)) return std::nullopt;
        if (auto it = created.find(o); it != created.end()) return it->second;
        if (auto it = utxo_.find(o); it != utxo_.end()) return it->second;
        return std::nullopt;
    };

    Amount fees = 0;
    for (size_t ti = 0; ti < b.txs.size(); ti++) {
        const Transaction& tx = b.txs[ti];
        Hash256 txid = tx.txid();
        if (!tx.is_coinbase()) {
            std::vector<Coin> coins;
            for (auto& in : tx.ins) {
                auto c = find(in.prev);
                if (!c) { if (why) *why = "missing-or-spent-input in " + txid.hex().substr(0, 16); return false; }
                coins.push_back(*c);
            }
            TxResult r = check_tx_inputs(tx, coins, height, p_.genesis_hash, verify);
            if (!r.ok) { if (why) *why = "tx " + txid.hex().substr(0, 16) + ": " + r.reason; return false; }
            fees += r.fee;
            for (size_t i = 0; i < tx.ins.size(); i++) {
                const OutPoint& o = tx.ins[i].prev;
                if (created.erase(o) == 0) { spent.insert(o); undo.spent.push_back({o, coins[i]}); }
            }
        }
        for (uint32_t n = 0; n < tx.outs.size(); n++)
            created[OutPoint{txid, n}] = Coin{tx.outs[n], height, tx.is_coinbase()};
    }
    if (idx->height > 0 && b.txs[0].total_out() > block_subsidy(height) + fees) {
        if (why) *why = "coinbase-pays-too-much";
        return false;
    }

    if (idx->height > 0 && !write_undo(idx, undo)) { if (why) *why = "undo-write-failed"; return false; }
    for (auto& o : spent) spend_coin(o);
    for (auto& [o, c] : created) add_coin(o, c);
    chain_.push_back(idx);
    index_block_txs(b, idx, true);
    for (auto& cb : on_connect) cb(b, idx);
    if (prune_) prune_at(idx->height - PRUNE_DEPTH);
    return true;
}

bool Chainstate::disconnect_tip(std::string* why) {
    BlockIndex* t = tip();
    if (t->height == 0) { if (why) *why = "cannot-disconnect-genesis"; return false; }
    Block b;
    Undo u;
    if (!read_block(t, b, false) || !read_undo(t, u)) { if (why) *why = "missing-undo-data"; return false; }
    for (auto& tx : b.txs) {
        Hash256 id = tx.txid();
        for (uint32_t n = 0; n < tx.outs.size(); n++) spend_coin(OutPoint{id, n});
    }
    for (auto& [o, c] : u.spent) add_coin(o, c);
    index_block_txs(b, t, false);
    chain_.pop_back();
    for (auto& cb : on_disconnect) cb(b, t);
    return true;
}

void Chainstate::prune_at(int64_t h) {
    BlockIndex* b = at_height(h);
    if (!b || h <= 0) return;
    std::error_code ec;
    fs::remove(witness_path(b->hash), ec);
    fs::remove(undo_path(b->hash), ec);
}

void Chainstate::activate_best_chain() {
    std::lock_guard lock(mu);
    BlockIndex* start = tip();
    for (int guard = 0; guard < 1000000; guard++) {
        BlockIndex* cand = best_candidate();
        if (!cand || cand == tip() || cand->chainwork <= tip()->chainwork) break;
        // fork point
        BlockIndex* fork = ancestor(cand, std::min(cand->height, tip()->height));
        while (fork && !in_active_chain(fork)) fork = fork->prev;
        if (!fork) break;
        bool ok = true;
        while (tip() != fork) {
            std::string why;
            if (!disconnect_tip(&why)) { logf("reorg aborted: %s", why.c_str()); ok = false; break; }
        }
        if (!ok) break;
        std::vector<BlockIndex*> path;
        for (BlockIndex* w = cand; w != fork; w = w->prev) path.push_back(w);
        std::reverse(path.begin(), path.end());
        bool stalled = false;
        for (BlockIndex* b : path) {
            std::string why;
            if (!connect_block(b, &why)) {
                if (why == "missing-witness" || why == "read-failed") { stalled = true; break; }
                logf("block %lld %s invalid: %s", (long long)b->height, b->hash.hex().substr(0, 16).c_str(), why.c_str());
                mark_failed(b);
                break;
            }
            if (++blocks_since_flush_ >= (is_initial_sync() ? 5000 : 100)) flush();
        }
        if (stalled) break;
    }
    // Drop candidates that can no longer win (keeps the set small).
    while (!candidates_.empty() && (*candidates_.begin())->chainwork < tip()->chainwork)
        candidates_.erase(candidates_.begin());
    if (tip() != start) {
        if (!is_initial_sync() || tip()->height % 1000 == 0)
            logf("new tip %lld %s", (long long)tip()->height, tip()->hash.hex().substr(0, 16).c_str());
        for (auto& cb : on_tip) cb(tip());
    }
}

} // namespace quant
