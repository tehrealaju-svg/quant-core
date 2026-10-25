// A complete Quant full node: chain + mempool + P2P + miner + wallet + RPC dispatcher.
// Used by quantd (headless, Raspberry Pi) and embedded in the desktop client.
#pragma once
#include <memory>
#include <string>

#include <json.hpp>

#include "miner/miner.h"
#include "net/p2p.h"
#include "wallet/wallet.h"

namespace quant {

using json = nlohmann::json;

struct NodeConfig {
    Network net = Network::Test;
    std::string datadir;      // base dir; the node uses <datadir>/<network>
    bool prune = true;
    P2POptions p2p;
    bool enable_p2p = true;
    int mine_threads = 0;
    std::string mine_address; // empty = wallet address
    std::string wallet_password;
    bool log_stdout = true;
};

struct RpcError : std::runtime_error { using std::runtime_error::runtime_error; };

std::string default_datadir();

class Node {
public:
    struct PoolPoint { int64_t height; uint64_t time; Amount qnt, tok; };
    struct TradePoint { int64_t height; uint64_t time; Hash256 txid; bool sell; Amount in, out; Hash256 trader; };
    explicit Node(NodeConfig cfg);
    ~Node();

    bool start(std::string* err);
    void stop();

    // Wallet management.
    bool has_wallet_file() const;
    bool wallet_loaded() const { return wallet_ != nullptr; }
    bool open_wallet(const std::string& password, std::string* err);
    bool create_wallet(const std::string& mnemonic, const std::string& passphrase, const std::string& password,
                       bool restored, std::string* err);
    Wallet* wallet() { return wallet_.get(); }

    // Send from the wallet and broadcast. Returns txid.
    std::string send(const std::vector<Wallet::Dest>& dests, Amount fee_per_kb, bool subtract_fee, const std::string& note);
    // Broadcast a transaction already built + signed by the wallet (e.g. after a confirm dialog).
    std::string broadcast(const Transaction& tx, const std::string& note);
    bool start_mining(int threads, const std::string& address, std::string* err);
    void stop_mining() { if (miner_) miner_->stop(); }

    json rpc(const std::string& method, const json& params);
    std::vector<std::string> rpc_commands() const;

    Chainstate& chain() { return *cs_; }
    Mempool& mempool() { return *mp_; }
    P2P* p2p() { return p2p_.get(); }
    Miner& miner() { return *miner_; }
    const ChainParams& params() const { return p_; }
    const NodeConfig& config() const { return cfg_; }
    const std::string& dir() const { return dir_; }
    bool stop_requested() const { return stop_requested_; }

private:
    void wallet_catch_up();
    void wallet_refresh_coins();
    json block_json(const Block& b, const BlockIndex* idx, bool verbose);
    json tx_json(const Transaction& tx, const Hash256* block, int64_t height);
    json out_json(const TxOut& o, const StateReader& st, int64_t n = -1);
    json op_json(const TxOp& op, const StateReader& st);
    json pool_json(const Pool& p, const StateReader& st);
    json token_json(const TokenInfo& t, const StateReader& st);
    int asset_decimals(const Hash256& a, const StateReader& st);
    std::string asset_label(const Hash256& a, const StateReader& st);
    Hash256 resolve_token(const std::string& s);

    NodeConfig cfg_;
    const ChainParams& p_;
    std::string dir_;
    std::unique_ptr<Chainstate> cs_;
    std::unique_ptr<Mempool> mp_;
    std::unique_ptr<P2P> p2p_;
    std::unique_ptr<Miner> miner_;
    std::unique_ptr<Wallet> wallet_;
    int64_t wallet_saved_height_ = 0;
    int64_t wallet_saved_time_ = 0;
    // Pool reserves after every block that touched the pool (price charts). Persisted in poolhist.dat.
    std::map<Hash256, std::vector<PoolPoint>> pool_hist_;
    std::map<Hash256, std::vector<TradePoint>> trades_; // swaps per token, oldest first (trades.dat)
    FILE* f_trades_ = nullptr;
    FILE* f_poolhist_ = nullptr;
    void pool_hist_load();
    void pool_hist_connect(const Block& b, const BlockIndex* idx);
    void pool_hist_disconnect(const BlockIndex* idx);
    void trades_load();
    void trades_compact();
    void trades_connect(const Block& b, const BlockIndex* idx);
    void trades_disconnect(const BlockIndex* idx);
    bool started_ = false;
    bool stop_requested_ = false;
};

} // namespace quant
