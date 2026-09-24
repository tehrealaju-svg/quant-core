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
    std::string send(const std::vector<Wallet::Dest>& dests, Amount fee_per_kb, bool subtract_fee, const std::string& note,
                     bool use_backup = false);
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

    NodeConfig cfg_;
    const ChainParams& p_;
    std::string dir_;
    std::unique_ptr<Chainstate> cs_;
    std::unique_ptr<Mempool> mp_;
    std::unique_ptr<P2P> p2p_;
    std::unique_ptr<Miner> miner_;
    std::unique_ptr<Wallet> wallet_;
    int64_t wallet_saved_height_ = 0;
    bool started_ = false;
    bool stop_requested_ = false;
};

} // namespace quant
