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
    w.varint(c.out.value);
    if (c.out.is_qnt()) w.u8(0); else { w.u8(1); w.hash(c.out.asset); }
    w.hash(c.out.addr);
    w.varint(c.height); w.u8(c.coinbase ? 1 : 0);
}
static Coin read_coin(Reader& r) {
    Coin c;
    c.out.value = r.varint();
    if (r.u8()) c.out.asset = r.hash();
    c.out.addr = r.hash();
    c.height = r.varint(); c.coinbase = r.u8() != 0;
    return c;
}
static void write_token(Writer& w, const TokenInfo& t) {
    w.hash(t.id); w.str(t.ticker); w.str(t.name); w.str(t.uri); w.u8(t.decimals);
    w.varint(t.supply); w.hash(t.create_txid); w.varint(t.height);
}
static TokenInfo read_token(Reader& r) {
    TokenInfo t;
    t.id = r.hash(); t.ticker = r.str(MAX_TICKER); t.name = r.str(MAX_TOKEN_NAME); t.uri = r.str(MAX_TOKEN_URI);
    t.decimals = r.u8(); t.supply = r.varint(); t.create_txid = r.hash(); t.height = r.varint();
    return t;
}
static void write_pool(Writer& w, const Pool& p) { w.hash(p.token); w.varint(p.qnt); w.varint(p.tok); w.varint(p.shares); }
static Pool read_pool(Reader& r) {
    Pool p; p.token = r.hash(); p.qnt = r.varint(); p.tok = r.varint(); p.shares = r.varint();
    return p;
}
constexpr uint32_t STATE_MAGIC = 0x32545351; // "QST2"

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

    // A node bootstrapped from a snapshot has no block data at or below the snapshot block.
    Bytes base;
    if (read_file(dir_ + "/base.dat", base) && base.size() == 32) {
        Hash256 bh; std::memcpy(bh.data(), base.data(), 32);
        if (BlockIndex* b = lookup(bh)) { b->from_snapshot = true; snapshot_base_ = b->height; }
    }

    // chain_data flags in height order
    std::vector<BlockIndex*> all;
    for (auto& [h, b] : index_) all.push_back(b);
    std::sort(all.begin(), all.end(), [](auto* a, auto* b) { return a->height < b->height; });
    for (auto* b : all) {
        b->chain_data = b->from_snapshot || (b->have_data && (!b->prev || b->prev->chain_data));
        if (b->chain_data) candidates_.insert(b);
    }

    scan_snapshots();
    if (!load_tip_state(err)) return false;

    // tx index for the explorer: scan the active chain's core data.
    for (auto* b : chain_) {
        Block blk;
        if (b->have_data && read_block(b, blk, false)) index_block_txs(blk, b, true);
    }
    logf("loaded %zu headers, chain height %lld, best header %lld, %zu coins, %zu tokens, %zu pools",
         index_.size(), (long long)height(), (long long)best_header_->height, utxo_.size(), tokens_.size(), pools_.size());
    activate_best_chain();
    return true;
}

void Chainstate::clear_state() {
    utxo_.clear(); by_addr_.clear(); tokens_.clear(); pools_.clear(); supply_ = 0;
}

Bytes Chainstate::serialize_state() const {
    Writer w;
    w.u32le(STATE_MAGIC);
    w.hash(tip()->hash);
    w.varint(uint64_t(height()));
    std::vector<std::pair<OutPoint, const Coin*>> coins;
    coins.reserve(utxo_.size());
    for (auto& [o, c] : utxo_) coins.push_back({o, &c});
    std::sort(coins.begin(), coins.end(), [](auto& a, auto& b) { return a.first < b.first; });
    w.varint(coins.size());
    for (auto& [o, c] : coins) { w.hash(o.txid); w.varint(o.n); write_coin(w, *c); }
    auto toks = all_tokens();
    w.varint(toks.size());
    for (auto& t : toks) write_token(w, t);
    auto pls = all_pools();
    w.varint(pls.size());
    for (auto& p : pls) write_pool(w, p);
    return std::move(w.buf);
}

Hash256 Chainstate::state_hash(const Bytes& snap) { return blake3_tagged(ctx::STATE, snap); }

bool Chainstate::parse_state(const Bytes& b, Hash256& block, int64_t& h) {
    clear_state();
    try {
        Reader r(b);
        if (r.u32le() != STATE_MAGIC) throw SerializeError("magic");
        block = r.hash();
        h = int64_t(r.varint());
        uint64_t n = r.varint();
        for (uint64_t i = 0; i < n; i++) {
            OutPoint o; o.txid = r.hash(); o.n = uint32_t(r.varint());
            add_coin(o, read_coin(r));
        }
        n = r.varint();
        for (uint64_t i = 0; i < n; i++) { auto t = read_token(r); tokens_[t.id] = t; }
        n = r.varint();
        for (uint64_t i = 0; i < n; i++) { auto p = read_pool(r); pools_[p.token] = p; supply_ += p.qnt; }
        if (!r.empty()) throw SerializeError("trailing data");
    } catch (const std::exception& e) {
        logf("state parse failed: %s", e.what());
        clear_state();
        return false;
    }
    return true;
}

bool Chainstate::load_tip_state(std::string* err) {
    Bytes sb;
    BlockIndex* g = lookup(p_.genesis_hash);
    chain_.assign(1, g);
    if (!read_file(dir_ + "/utxo.dat", sb) || sb.size() < 40) {
        if (snapshot_base_) { if (err) *err = "utxo.dat missing on a snapshot-bootstrapped node; delete the data directory to resync"; return false; }
        return true;
    }
    Hash256 check = blake3(sb.data(), sb.size() - 32);
    Hash256 tiph; int64_t th = 0;
    bool ok = std::memcmp(check.data(), sb.data() + sb.size() - 32, 32) == 0;
    if (ok) { sb.resize(sb.size() - 32); ok = parse_state(sb, tiph, th); }
    BlockIndex* t = ok ? lookup(tiph) : nullptr;
    if (!t || !t->chain_data || t->height != th) {
        clear_state();
        if (snapshot_base_) { if (err) *err = "utxo.dat unusable on a snapshot-bootstrapped node; delete the data directory to resync"; return false; }
        logf("utxo.dat unusable - rebuilding from blocks");
        return true;
    }
    chain_.resize(t->height + 1);
    for (BlockIndex* w = t; w; w = w->prev) chain_[w->height] = w;
    return true;
}

void Chainstate::flush() {
    std::lock_guard lock(mu);
    Bytes s = serialize_state();
    Hash256 check = blake3(s);
    s.insert(s.end(), check.b.begin(), check.b.end());
    if (!write_file_atomic(dir_ + "/utxo.dat", s)) logf("WARNING: failed to write utxo.dat");
    blocks_since_flush_ = 0;
}

// ---------------------------------------------------------------- snapshots
std::string Chainstate::snapshot_path(const Hash256& h) const { return dir_ + "/snapshots/" + h.hex() + ".snap"; }

void Chainstate::scan_snapshots() {
    std::error_code ec;
    fs::create_directories(dir_ + "/snapshots", ec);
    for (auto& e : fs::directory_iterator(dir_ + "/snapshots", ec)) {
        auto name = e.path().filename().string();
        if (name.size() != 64 + 5 || e.path().extension() != ".snap") continue;
        auto bh = Hash256::from_hex(name.substr(0, 64));
        Bytes b;
        if (!bh || !read_file(e.path().string(), b)) continue;
        snapshot_hash_[*bh] = state_hash(b);
    }
}

bool Chainstate::read_snapshot_file(const Hash256& block, Bytes& out) const {
    if (!snapshot_hash_.count(block)) return false;
    return read_file(snapshot_path(block), out);
}

// Called after connecting a block at a multiple of p_.snapshot_interval.
void Chainstate::write_commit_snapshot(BlockIndex* idx) {
    Bytes s = serialize_state();
    if (!write_file_atomic(snapshot_path(idx->hash), s)) { logf("WARNING: failed to write snapshot"); return; }
    snapshot_hash_[idx->hash] = state_hash(s);
    // Keep the newest 3 snapshots on the active chain (plus the one we bootstrapped from).
    std::vector<std::pair<int64_t, Hash256>> held;
    for (auto& [bh, sh] : snapshot_hash_) {
        BlockIndex* b = lookup(bh);
        held.push_back({b && in_active_chain(b) ? b->height : -1, bh});
    }
    std::sort(held.begin(), held.end(), std::greater<>());
    for (size_t i = 3; i < held.size(); i++) {
        BlockIndex* b = lookup(held[i].second);
        if (b && b->from_snapshot) continue;
        std::error_code ec;
        fs::remove(snapshot_path(held[i].second), ec);
        snapshot_hash_.erase(held[i].second);
    }
}

std::optional<Hash256> Chainstate::committed_hash_for(const BlockIndex* block) const {
    if (!block || !best_header_) return std::nullopt;
    int64_t ch = block->height + p_.snapshot_delay;
    if (!is_commit_height(ch) || best_header_->height < ch) return std::nullopt;
    BlockIndex* c = ancestor(best_header_, ch);
    if (!c || ancestor(c, block->height) != block) return std::nullopt;
    return c->header.state_commit;
}

std::optional<std::pair<Hash256, std::string>> Chainstate::best_snapshot_file() const {
    std::optional<std::pair<Hash256, std::string>> best;
    int64_t best_h = -1;
    for (auto& [bh, sh] : snapshot_hash_) {
        BlockIndex* b = lookup(bh);
        auto c = committed_hash_for(b);
        if (!c || *c != sh || b->height <= best_h) continue;
        best_h = b->height;
        best = std::make_pair(bh, snapshot_path(bh));
    }
    return best;
}

bool Chainstate::load_snapshot_bytes(const Bytes& snap, std::string* why) {
    std::lock_guard lock(mu);
    auto fail = [&](const char* r) { if (why) *why = r; return false; };
    if (height() > 0) return fail("node-not-fresh");
    if (snap.size() < 4 + 32 + 1) return fail("short");
    Reader r(snap);
    if (r.u32le() != STATE_MAGIC) return fail("bad-magic");
    Hash256 bh = r.hash();
    BlockIndex* b = lookup(bh);
    if (!b) return fail("unknown-block");
    auto c = committed_hash_for(b);
    if (!c) return fail("no-commitment-in-best-chain");
    Hash256 sh = state_hash(snap);
    if (*c != sh) return fail("hash-mismatch");
    Hash256 got; int64_t h = 0;
    if (!parse_state(snap, got, h) || h != b->height) { clear_state(); return fail("parse-failed"); }
    if (!write_file_atomic(snapshot_path(bh), snap)) return fail("disk-write-failed");
    snapshot_hash_[bh] = sh;
    if (!write_file_atomic(dir_ + "/base.dat", Bytes(bh.b.begin(), bh.b.end()))) return fail("disk-write-failed");
    b->from_snapshot = true;
    snapshot_base_ = b->height;
    chain_.assign(b->height + 1, nullptr);
    for (BlockIndex* w = b; w; w = w->prev) chain_[w->height] = w;
    txindex_.clear();
    b->chain_data = true;
    candidates_.insert(b);
    for (auto* ch : b->children) update_chain_data(ch);
    flush();
    logf("bootstrapped from snapshot at height %lld (%zu coins, %zu tokens, %zu pools)",
         (long long)b->height, utxo_.size(), tokens_.size(), pools_.size());
    activate_best_chain();
    return true;
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

std::optional<Coin> Chainstate::coin(const OutPoint& o) const {
    auto it = utxo_.find(o);
    if (it == utxo_.end()) return std::nullopt;
    return it->second;
}

std::optional<TokenInfo> Chainstate::token(const Hash256& id) const {
    auto it = tokens_.find(id);
    if (it == tokens_.end()) return std::nullopt;
    return it->second;
}

std::optional<Pool> Chainstate::pool(const Hash256& t) const {
    auto it = pools_.find(t);
    if (it == pools_.end()) return std::nullopt;
    return it->second;
}

std::vector<TokenInfo> Chainstate::all_tokens() const {
    std::vector<TokenInfo> v;
    for (auto& [id, t] : tokens_) v.push_back(t);
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.id < b.id; });
    return v;
}

std::vector<Pool> Chainstate::all_pools() const {
    std::vector<Pool> v;
    for (auto& [id, p] : pools_) v.push_back(p);
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.token < b.token; });
    return v;
}

std::map<Hash256, Amount> Chainstate::balances_for_address(const Hash256& addr) const {
    std::map<Hash256, Amount> m;
    for (auto& [o, c] : coins_for_address(addr)) m[c.out.asset] += c.out.value;
    return m;
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
    s.issued = issued_through(uint64_t(height()));
    s.tokens = tokens_.size();
    s.pools = pools_.size();
    std::error_code ec;
    s.disk_blocks = fs::file_size(dir_ + "/blocks.dat", ec);
    s.disk_headers = fs::file_size(dir_ + "/headers.dat", ec);
    for (auto& e : fs::directory_iterator(dir_ + "/witness", ec)) s.disk_witness += e.file_size(ec);
    for (auto& e : fs::directory_iterator(dir_ + "/snapshots", ec)) s.disk_snapshots += e.file_size(ec);
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
    if (c.out.is_qnt()) supply_ += c.out.value;
}

void Chainstate::spend_coin(const OutPoint& o) {
    auto it = utxo_.find(o);
    if (it == utxo_.end()) return;
    auto a = by_addr_.find(it->second.out.addr);
    if (a != by_addr_.end()) { a->second.erase(o); if (a->second.empty()) by_addr_.erase(a); }
    if (it->second.out.is_qnt()) supply_ -= it->second.out.value;
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
    if (h.version != 2) return fail("bad-version");
    if (is_commit_height(prev->height + 1) == h.state_commit.is_zero()) return fail("bad-state-commit-presence");
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
    w.varint(u.pools_before.size());
    for (auto& [t, p] : u.pools_before) {
        w.hash(t);
        if (p) { w.u8(1); write_pool(w, *p); } else w.u8(0);
    }
    w.varint(u.tokens_created.size());
    for (auto& t : u.tokens_created) w.hash(t);
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
        n = r.varint();
        for (uint64_t i = 0; i < n; i++) {
            Hash256 t = r.hash();
            std::optional<Pool> p;
            if (r.u8()) p = read_pool(r);
            u.pools_before.push_back({t, p});
        }
        n = r.varint();
        for (uint64_t i = 0; i < n; i++) u.tokens_created.push_back(r.hash());
    } catch (...) { return false; }
    return true;
}

void Chainstate::set_pool(const Hash256& token, const std::optional<Pool>& p) {
    if (auto it = pools_.find(token); it != pools_.end()) { supply_ -= it->second.qnt; pools_.erase(it); }
    if (p) { pools_[token] = *p; supply_ += p->qnt; }
}

bool Chainstate::connect_block(BlockIndex* idx, std::string* why) {
    auto fail = [&](const std::string& r) { if (why) *why = r; return false; };
    Block b;
    bool got_witness = false;
    if (!read_block(idx, b, true, &got_witness)) return fail("read-failed");
    bool deep = best_header_ && idx->height + PRUNE_DEPTH <= best_header_->height;
    if (!got_witness && !deep && idx->height > 0) return fail("missing-witness");
    bool verify = got_witness && idx->height > 0;
    const uint64_t height = uint64_t(idx->height);

    // The header must commit to the state snapshot taken p_.snapshot_delay blocks ago.
    if (is_commit_height(idx->height)) {
        BlockIndex* base = ancestor(idx, idx->height - p_.snapshot_delay);
        auto it = base ? snapshot_hash_.find(base->hash) : snapshot_hash_.end();
        if (it == snapshot_hash_.end()) logf("WARNING: no local snapshot to check the commitment in block %lld", (long long)idx->height);
        else if (it->second != idx->header.state_commit) return fail("bad-state-commit");
    }

    // Apply into an overlay so a bad tx leaves the state untouched.
    LedgerView view(*this);
    view.apply_coinbase(b.txs[0], height);
    Amount fees = 0;
    for (size_t ti = 1; ti < b.txs.size(); ti++) {
        TxResult r = view.apply(b.txs[ti], height, p_.genesis_hash, verify);
        if (!r.ok) return fail("tx " + b.txs[ti].txid().hex().substr(0, 16) + ": " + r.reason);
        fees += r.fee;
    }
    if (idx->height > 0 && b.txs[0].total_qnt_out() > block_subsidy(height) + fees) return fail("coinbase-pays-too-much");

    Undo undo;
    for (auto& [o, c] : view.spent_base()) undo.spent.push_back({o, c});
    for (auto& [t, p] : view.pools_before()) undo.pools_before.push_back({t, p});
    for (auto& [id, t] : view.new_tokens()) undo.tokens_created.push_back(id);
    if (idx->height > 0 && !write_undo(idx, undo)) return fail("undo-write-failed");

    for (auto& [o, c] : view.spent_base()) spend_coin(o);
    for (auto& [o, c] : view.created()) add_coin(o, c);
    for (auto& [id, t] : view.new_tokens()) tokens_[id] = t;
    for (auto& [t, p] : view.pools()) set_pool(t, p);
    chain_.push_back(idx);
    index_block_txs(b, idx, true);
    for (auto& cb : on_connect) cb(b, idx);
    if (idx->height > 0 && idx->height % p_.snapshot_interval == 0) write_commit_snapshot(idx);
    if (prune_) prune_at(idx->height - PRUNE_DEPTH);
    return true;
}

bool Chainstate::disconnect_tip(std::string* why) {
    BlockIndex* t = tip();
    if (t->height == 0 || t->from_snapshot) { if (why) *why = "cannot-disconnect-base"; return false; }
    Block b;
    Undo u;
    if (!read_block(t, b, false) || !read_undo(t, u)) { if (why) *why = "missing-undo-data"; return false; }
    for (auto& tx : b.txs) {
        Hash256 id = tx.txid();
        for (uint32_t n = 0; n < tx.outs.size(); n++) spend_coin(OutPoint{id, n});
    }
    for (auto& [o, c] : u.spent) add_coin(o, c);
    for (auto& [tok, p] : u.pools_before) set_pool(tok, p);
    for (auto& id : u.tokens_created) tokens_.erase(id);
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

namespace quant {
Hash256 Chainstate::commit_for_next(BlockIndex* prev) const {
    int64_t h = prev->height + 1;
    if (!is_commit_height(h)) return Hash256{};
    BlockIndex* base = ancestor(prev, h - p_.snapshot_delay);
    auto s = base ? local_snapshot_hash(base->hash) : std::nullopt;
    return s ? *s : Hash256{};
}
} // namespace quant
