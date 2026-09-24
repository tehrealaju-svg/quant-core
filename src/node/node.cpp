#include "node/node.h"

#include <filesystem>

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
    cs_->on_tip.push_back([this](const BlockIndex* t) {
        if (miner_) miner_->notify_new_tip();
        if (!wallet_) return;
        wallet_refresh_coins();
        if (t->height - wallet_saved_height_ >= 10 || !cs_->is_initial_sync()) {
            wallet_->save();
            wallet_saved_height_ = t->height;
        }
    });
    mp_->on_added.push_back([this](const Transaction& tx) {
        if (!wallet_) return;
        bool mine = false;
        for (auto& o : tx.outs) mine |= wallet_->is_mine(o.addr);
        for (auto& c : wallet_->coins()) for (auto& in : tx.ins) mine |= c.op == in.prev;
        if (mine) wallet_->tx_broadcast(tx, "");
    });

    if (!cs_->load(err)) return false;
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
                       const std::string& note, bool use_backup) {
    if (!wallet_) throw RpcError("no wallet loaded");
    Transaction tx;
    Amount fee = 0;
    std::string err;
    int64_t h;
    { std::lock_guard l(cs_->mu); h = cs_->height(); }
    if (!wallet_->create_tx(dests, fee_per_kb, h, tx, &fee, &err, use_backup, subtract_fee)) throw RpcError(err);
    logf("sending %s QNT fee", format_amount(fee).c_str());
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
