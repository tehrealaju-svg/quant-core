#include "node/node.h"

#include <filesystem>
#include <set>

#include "consensus/limits.h"
#include "util/log.h"
#include "wallet/mnemonic.h"

namespace fs = std::filesystem;

namespace quant {

std::string default_datadir() {
#ifdef _WIN32
    const char* app = getenv("APPDATA");
    return std::string(app ? app : ".") + "\\Quant";
#else
    const char* home = getenv("HOME");
    return std::string(home ? home : ".") + "/.quant";
#endif
}

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)), p_(params_for(cfg_.net)) {
    if (cfg_.datadir.empty()) cfg_.datadir = default_datadir();
    dir_ = cfg_.datadir + "/" + p_.name;
}

Node::~Node() { stop(); }

bool Node::start(std::string* err) {
    if (p_.net == Network::Main && !p_.launched) {
        if (err) *err = "Quant mainnet has not launched yet. Use testnet (default) - see LAUNCH.md.";
        return false;
    }
    std::error_code ec;
    fs::create_directories(dir_, ec);
    if (ec) { if (err) *err = "cannot create data dir " + dir_; return false; }
    log_set_stdout(cfg_.log_stdout);
    log_set_file(dir_ + "/debug.log");
    logf("Quant node starting - network %s, data %s", p_.name.c_str(), dir_.c_str());

    cs_ = std::make_unique<Chainstate>(p_, dir_, cfg_.prune);
    mp_ = std::make_unique<Mempool>(*cs_);
    // Wallet hooks (the wallet may be opened later; callbacks check for it).
    cs_->on_connect.push_back([this](const Block& b, const BlockIndex* idx) {
        if (wallet_) wallet_->block_connected(b, idx->height);
    });
    cs_->on_disconnect.push_back([this](const Block& b, const BlockIndex* idx) {
        if (wallet_) wallet_->block_disconnected(b, idx->height);
    });
    cs_->on_connect.push_back([this](const Block& b, const BlockIndex* idx) { pool_hist_connect(b, idx); });
    cs_->on_disconnect.push_back([this](const Block&, const BlockIndex* idx) { pool_hist_disconnect(idx); });
    cs_->on_connect.push_back([this](const Block& b, const BlockIndex* idx) { trades_connect(b, idx); });
    cs_->on_disconnect.push_back([this](const Block&, const BlockIndex* idx) { trades_disconnect(idx); });
    cs_->on_connect.push_back([this](const Block& b, const BlockIndex* idx) { msgs_connect(b, idx); });
    cs_->on_disconnect.push_back([this](const Block&, const BlockIndex* idx) {
        while (!msgs_.empty() && msgs_.back().height >= idx->height) msgs_.pop_back();
    });
    cs_->on_tip.push_back([this](const BlockIndex* t) {
        if (miner_) miner_->notify_new_tip();
        if (!wallet_) return;
        // Coins are rebuilt on every new tip, but the encrypted file (slow key stretching) is
        // written at most once a minute; it is also saved on shutdown and after every send.
        wallet_refresh_coins();
        int64_t now = now_seconds();
        if (now - wallet_saved_time_ >= 60) {
            wallet_->save();
            wallet_saved_height_ = t->height;
            wallet_saved_time_ = now;
        }
    });
    mp_->on_added.push_back([this](const Transaction& tx) {
        if (!wallet_) return;
        bool mine = false;
        for (auto& o : tx.outs) mine |= wallet_->is_mine(o.addr);
        for (auto& c : wallet_->coins()) for (auto& in : tx.ins) mine |= c.op == in.prev;
        if (mine) wallet_->tx_broadcast(tx, "");
    });

    pool_hist_load();
    trades_load();
    msgs_load();
    if (!cs_->load(err)) return false;
    {
        // Drop chart points above the loaded tip and compact the file.
        std::lock_guard l(cs_->mu);
        for (auto& [t, v] : pool_hist_)
            while (!v.empty() && v.back().height > cs_->height()) v.pop_back();
        if (f_poolhist_) fclose(f_poolhist_);
        f_poolhist_ = fopen((dir_ + "/poolhist.dat").c_str(), "wb");
        for (auto& [t, v] : pool_hist_)
            for (auto& pt : v) { Writer w; w.hash(t); w.u64le(uint64_t(pt.height)); w.u64le(pt.time); w.u64le(pt.qnt); w.u64le(pt.tok); fwrite(w.buf.data(), 1, w.buf.size(), f_poolhist_); }
        if (f_poolhist_) fflush(f_poolhist_);
        trades_compact();
        msgs_compact();
    }
    miner_ = std::make_unique<Miner>(*cs_, *mp_);
    miner_->on_found = [this](const Block& b) {
        std::string why;
        if (!cs_->accept_block(b, true, &why)) logf("miner: our block was rejected: %s", why.c_str());
    };

    if (cfg_.enable_p2p) {
        cfg_.p2p.datadir = dir_;
        p2p_ = std::make_unique<P2P>(*cs_, *mp_, cfg_.p2p);
        if (!p2p_->start(err)) return false;
    }
    if (has_wallet_file()) {
        std::string werr;
        if (!open_wallet(cfg_.wallet_password, &werr)) logf("wallet not opened: %s", werr.c_str());
    }
    started_ = true;
    if (cfg_.mine_threads > 0) {
        std::string merr;
        if (!start_mining(cfg_.mine_threads, cfg_.mine_address, &merr)) logf("mining not started: %s", merr.c_str());
    }
    return true;
}

void Node::stop() {
    if (!started_) return;
    started_ = false;
    logf("shutting down");
    if (miner_) miner_->stop();
    if (p2p_) p2p_->stop();
    if (cs_) cs_->flush();
    if (wallet_) wallet_->save();
    if (f_poolhist_) { fclose(f_poolhist_); f_poolhist_ = nullptr; }
    if (f_trades_) { fclose(f_trades_); f_trades_ = nullptr; }
    if (f_msgs_) { fclose(f_msgs_); f_msgs_ = nullptr; }
}

// ---------------------------------------------------------------- wallet
bool Node::has_wallet_file() const { return Wallet::exists(dir_ + "/wallet.qwl"); }

bool Node::open_wallet(const std::string& password, std::string* err) {
    auto w = Wallet::open(dir_ + "/wallet.qwl", p_, password, err);
    if (!w) return false;
    std::lock_guard l(cs_->mu);
    wallet_ = std::move(w);
    wallet_catch_up();
    logf("wallet opened (%zu addresses)", wallet_->issued_keys().size());
    return true;
}

bool Node::create_wallet(const std::string& mnemonic, const std::string& passphrase, const std::string& password,
                         bool restored, std::string* err) {
    if (has_wallet_file()) { if (err) *err = "a wallet already exists in " + dir_; return false; }
    int64_t birth;
    { std::lock_guard l(cs_->mu); birth = restored ? 0 : cs_->height(); }
    auto w = Wallet::create(dir_ + "/wallet.qwl", p_, mnemonic, passphrase, password, birth, err);
    if (!w) return false;
    std::lock_guard l(cs_->mu);
    wallet_ = std::move(w);
    wallet_catch_up();
    wallet_->save();
    logf("wallet created");
    return true;
}

void Node::wallet_catch_up() {
    std::lock_guard l(cs_->mu);
    if (!wallet_) return;
    int64_t start = wallet_->birth_height;
    BlockIndex* synced = cs_->lookup(wallet_->synced_tip);
    if (wallet_->synced_height >= 0 && synced && cs_->in_active_chain(synced)) start = wallet_->synced_height + 1;
    if (start < cs_->height()) logf("wallet: scanning blocks %lld..%lld", (long long)start, (long long)cs_->height());
    for (int64_t h = std::max<int64_t>(start, 0); h <= cs_->height(); h++) {
        Block b;
        if (cs_->read_block(cs_->at_height(h), b, false)) wallet_->block_connected(b, h);
    }
    wallet_refresh_coins();
    wallet_->save();
}

void Node::wallet_refresh_coins() {
    std::lock_guard l(cs_->mu);
    if (!wallet_) return;
    for (int round = 0; round < 10; round++) {
        auto watched = wallet_->watched_addresses();
        std::vector<WalletCoin> coins;
        std::set<Hash256> mine(watched.begin(), watched.end());
        for (auto& a : watched)
            for (auto& [op, c] : cs_->coins_for_address(a))
                coins.push_back(WalletCoin{op, c.out, int64_t(c.height), c.coinbase, mp_->spends(op)});
        for (auto* e : mp_->all())
            for (uint32_t i = 0; i < e->tx.outs.size(); i++)
                if (mine.count(e->tx.outs[i].addr))
                    coins.push_back(WalletCoin{OutPoint{e->txid, i}, e->tx.outs[i], -1, false, mp_->spends(OutPoint{e->txid, i})});
        wallet_->replace_coins(coins);
        if (wallet_->watched_addresses().size() == watched.size()) break; // lookahead stable
    }
}

std::string Node::send(const std::vector<Wallet::Dest>& dests, Amount fee_per_kb, bool subtract_fee,
                       const std::string& note) {
    if (!wallet_) throw RpcError("no wallet loaded");
    Transaction tx;
    Amount fee = 0;
    std::string err;
    int64_t h;
    { std::lock_guard l(cs_->mu); h = cs_->height(); }
    if (!wallet_->create_tx(dests, fee_per_kb, h, tx, &fee, &err, subtract_fee)) throw RpcError(err);
    logf("sending, fee %s QNT", format_amount(fee).c_str());
    return broadcast(tx, note);
}

std::string Node::broadcast(const Transaction& tx, const std::string& note) {
    std::string err;
    if (!mp_->accept(tx, &err)) throw RpcError("transaction rejected: " + err);
    if (wallet_) wallet_->tx_broadcast(tx, note);
    if (p2p_) p2p_->broadcast_tx(tx);
    logf("broadcast tx %s", tx.txid().hex().c_str());
    return tx.txid().hex();
}

bool Node::start_mining(int threads, const std::string& address, std::string* err) {
    Hash256 payout;
    if (!address.empty()) {
        uint8_t v;
        if (!decode_address(p_, address, v, payout)) { if (err) *err = "invalid mining address"; return false; }
    } else if (wallet_) {
        auto keys = wallet_->issued_keys();
        payout = keys.empty() ? Hash256{} : keys.front()->addr;
        std::string a = wallet_->address_string(payout);
        cfg_.mine_address = a;
    } else {
        if (err) *err = "create or open a wallet first, or pass a mining address";
        return false;
    }
    miner_->start(threads, payout);
    return true;
}

} // namespace quant

namespace quant {
static constexpr size_t POOLHIST_REC = 32 + 8 * 4;

static void pool_hist_put(std::vector<Node::PoolPoint>& v, const Node::PoolPoint& pt) {
    while (!v.empty() && v.back().height >= pt.height) v.pop_back();
    v.push_back(pt);
}

void Node::pool_hist_load() {
    FILE* f = fopen((dir_ + "/poolhist.dat").c_str(), "rb");
    if (!f) return;
    uint8_t rec[POOLHIST_REC];
    while (fread(rec, 1, sizeof rec, f) == sizeof rec) {
        Reader r(rec, sizeof rec);
        Hash256 t = r.hash();
        PoolPoint pt;
        pt.height = int64_t(r.u64le()); pt.time = r.u64le(); pt.qnt = r.u64le(); pt.tok = r.u64le();
        pool_hist_put(pool_hist_[t], pt);
    }
    fclose(f);
}

void Node::pool_hist_connect(const Block& b, const BlockIndex* idx) {
    std::set<Hash256> touched;
    for (auto& tx : b.txs)
        for (auto& op : tx.ops)
            std::visit([&](auto& o) {
                using T = std::decay_t<decltype(o)>;
                if constexpr (!std::is_same_v<T, OpCreateToken> && !std::is_same_v<T, OpMessage>) touched.insert(o.token);
            }, op);
    for (auto& t : touched) {
        auto pl = cs_->pool(t);
        if (!pl) continue;
        PoolPoint pt{idx->height, b.header.time, pl->qnt, pl->tok};
        pool_hist_put(pool_hist_[t], pt);
        if (f_poolhist_) {
            Writer w; w.hash(t); w.u64le(uint64_t(pt.height)); w.u64le(pt.time); w.u64le(pt.qnt); w.u64le(pt.tok);
            fwrite(w.buf.data(), 1, w.buf.size(), f_poolhist_);
            fflush(f_poolhist_);
        }
    }
}

void Node::pool_hist_disconnect(const BlockIndex* idx) {
    for (auto& [t, v] : pool_hist_)
        while (!v.empty() && v.back().height >= idx->height) v.pop_back();
}
} // namespace quant

namespace quant {
// ---------------------------------------------------------------- trade index (swaps per token)
static constexpr size_t TRADE_REC = 32 + 8 + 8 + 32 + 1 + 8 + 8 + 32;

static void write_trade(FILE* f, const Hash256& token, const Node::TradePoint& t) {
    if (!f) return;
    Writer w;
    w.hash(token); w.u64le(uint64_t(t.height)); w.u64le(t.time); w.hash(t.txid); w.u8(t.sell);
    w.u64le(t.in); w.u64le(t.out); w.hash(t.trader);
    fwrite(w.buf.data(), 1, w.buf.size(), f);
}

void Node::trades_load() {
    FILE* f = fopen((dir_ + "/trades.dat").c_str(), "rb");
    if (!f) return;
    uint8_t rec[TRADE_REC];
    while (fread(rec, 1, sizeof rec, f) == sizeof rec) {
        Reader r(rec, sizeof rec);
        Hash256 tok = r.hash();
        TradePoint t;
        t.height = int64_t(r.u64le()); t.time = r.u64le(); t.txid = r.hash(); t.sell = r.u8() != 0;
        t.in = r.u64le(); t.out = r.u64le(); t.trader = r.hash();
        auto& v = trades_[tok];
        while (!v.empty() && v.back().height > t.height) v.pop_back(); // reorged away
        bool dup = false;
        for (auto it = v.rbegin(); it != v.rend() && it->height == t.height; ++it)
            if (it->txid == t.txid && it->in == t.in && it->out == t.out) { dup = true; break; }
        if (!dup) v.push_back(t);
    }
    fclose(f);
}

void Node::trades_compact() {
    for (auto& [t, v] : trades_)
        while (!v.empty() && v.back().height > cs_->height()) v.pop_back();
    if (f_trades_) fclose(f_trades_);
    f_trades_ = fopen((dir_ + "/trades.dat").c_str(), "wb");
    for (auto& [tok, v] : trades_) for (auto& t : v) write_trade(f_trades_, tok, t);
    if (f_trades_) fflush(f_trades_);
}

void Node::trades_connect(const Block& b, const BlockIndex* idx) {
    bool trimmed_any = false;
    std::set<Hash256> trimmed;
    for (auto& tx : b.txs) {
        Hash256 id;
        bool have_id = false;
        for (auto& op : tx.ops) {
            auto* s = std::get_if<OpSwap>(&op);
            if (!s) continue;
            if (!have_id) { id = tx.txid(); have_id = true; }
            auto& v = trades_[s->token];
            if (trimmed.insert(s->token).second)
                while (!v.empty() && v.back().height >= idx->height) { v.pop_back(); trimmed_any = true; }
            TradePoint t{idx->height, b.header.time, id, s->sell, s->in, s->out, tx.outs.empty() ? Hash256{} : tx.outs[0].addr};
            v.push_back(t);
            write_trade(f_trades_, s->token, t);
        }
    }
    if (f_trades_) fflush(f_trades_);
    (void)trimmed_any;
}

void Node::trades_disconnect(const BlockIndex* idx) {
    for (auto& [t, v] : trades_)
        while (!v.empty() && v.back().height >= idx->height) v.pop_back();
}
} // namespace quant

namespace quant {
// ---------------------------------------------------------------- message index (OpMessage, chat + gifts)
static void write_msg(FILE* f, const Node::MsgPoint& m) {
    if (!f) return;
    Writer w;
    w.u64le(uint64_t(m.height)); w.u64le(m.time); w.hash(m.txid); w.hash(m.from); w.hash(m.to); w.u8(m.gift); w.str(m.text);
    Writer len; len.u32le(uint32_t(w.buf.size()));
    fwrite(len.buf.data(), 1, len.buf.size(), f);
    fwrite(w.buf.data(), 1, w.buf.size(), f);
}

void Node::msgs_load() {
    FILE* f = fopen((dir_ + "/messages.dat").c_str(), "rb");
    if (!f) return;
    uint8_t lb[4];
    while (fread(lb, 1, 4, f) == 4) {
        uint32_t n = uint32_t(lb[0]) | uint32_t(lb[1]) << 8 | uint32_t(lb[2]) << 16 | uint32_t(lb[3]) << 24;
        if (n > 1024) break;
        Bytes rec(n);
        if (fread(rec.data(), 1, n, f) != n) break;
        try {
            Reader r(rec.data(), rec.size());
            MsgPoint m;
            m.height = int64_t(r.u64le()); m.time = r.u64le(); m.txid = r.hash(); m.from = r.hash(); m.to = r.hash();
            m.gift = r.u8(); m.text = r.str(MAX_MESSAGE_TEXT);
            if (m.gift >= GIFT_COUNT) continue;
            while (!msgs_.empty() && msgs_.back().height > m.height) msgs_.pop_back(); // reorged away
            bool dup = false;
            for (auto it = msgs_.rbegin(); it != msgs_.rend() && it->height == m.height; ++it) dup |= it->txid == m.txid;
            if (!dup) msgs_.push_back(std::move(m));
        } catch (const std::exception&) { break; }
    }
    fclose(f);
}

void Node::msgs_compact() {
    while (!msgs_.empty() && msgs_.back().height > cs_->height()) msgs_.pop_back();
    if (f_msgs_) fclose(f_msgs_);
    f_msgs_ = fopen((dir_ + "/messages.dat").c_str(), "wb");
    for (auto& m : msgs_) write_msg(f_msgs_, m);
    if (f_msgs_) fflush(f_msgs_);
}

void Node::msgs_connect(const Block& b, const BlockIndex* idx) {
    while (!msgs_.empty() && msgs_.back().height >= idx->height) msgs_.pop_back();
    for (auto& tx : b.txs)
        for (auto& op : tx.ops)
            if (auto* m = std::get_if<OpMessage>(&op)) {
                MsgPoint p{idx->height, b.header.time, tx.txid(), m->from, m->to, m->gift, m->text};
                write_msg(f_msgs_, p);
                msgs_.push_back(std::move(p));
            }
    if (f_msgs_) fflush(f_msgs_);
}
} // namespace quant
