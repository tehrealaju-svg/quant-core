// quantd - headless Quant full node + miner (PC, Raspberry Pi, servers).
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>

#include "consensus/limits.h"
#include "node/httprpc.h"
#include "util/log.h"
#include "wallet/mnemonic.h"

using namespace quant;

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

static void usage() {
    printf(
        "quantd - Quant (QNT) post-quantum full node\n\n"
        "Usage: quantd [options]\n"
        "  -testnet            use the test network (default until mainnet launches)\n"
        "  -mainnet            use the main network\n"
        "  -regtest            private local test chain (instant blocks)\n"
        "  -datadir=<dir>      data directory (default %s)\n"
        "  -port=<n>           P2P port\n"
        "  -rpcport=<n>        RPC port (localhost only)\n"
        "  -addnode=<ip:port>  connect to a node (repeatable)\n"
        "  -connect=<ip:port>  connect ONLY to this node (repeatable; disables discovery)\n"
        "  -nodht -nolan -noupnp -nolisten   disable a discovery / networking feature\n"
        "  -noprune            keep all signatures (archive node)\n"
        "  -mine=<threads>     start mining\n"
        "  -mineaddress=<addr> pay mining rewards here (default: wallet)\n"
        "  -createwallet       create a wallet if none exists and print its seed words\n"
        "  -walletpassword=<p> password for the wallet file\n",
        default_datadir().c_str());
}

int main(int argc, char** argv) {
    NodeConfig cfg;
    uint16_t rpcport = 0;
    bool create_wallet = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a.rfind("--", 0) == 0) a = a.substr(1);
        auto val = [&](const char* k) -> std::string { std::string p = std::string(k) + "="; return a.rfind(p, 0) == 0 ? a.substr(p.size()) : ""; };
        if (a == "-h" || a == "-help" || a == "-?") { usage(); return 0; }
        else if (a == "-testnet") cfg.net = Network::Test;
        else if (a == "-mainnet") cfg.net = Network::Main;
        else if (a == "-regtest") cfg.net = Network::Regtest;
        else if (!val("-datadir").empty()) cfg.datadir = val("-datadir");
        else if (!val("-port").empty()) cfg.p2p.port = uint16_t(std::stoi(val("-port")));
        else if (!val("-rpcport").empty()) rpcport = uint16_t(std::stoi(val("-rpcport")));
        else if (!val("-addnode").empty()) cfg.p2p.addnodes.push_back(val("-addnode"));
        else if (!val("-connect").empty()) { cfg.p2p.addnodes.push_back(val("-connect")); cfg.p2p.connect_only = true; }
        else if (a == "-nodht") cfg.p2p.dht = false;
        else if (a == "-nolan") cfg.p2p.lan = false;
        else if (a == "-noupnp") cfg.p2p.upnp = false;
        else if (a == "-nolisten") cfg.p2p.listen = false;
        else if (a == "-noprune") cfg.prune = false;
        else if (!val("-mine").empty()) cfg.mine_threads = std::stoi(val("-mine"));
        else if (!val("-mineaddress").empty()) cfg.mine_address = val("-mineaddress");
        else if (!val("-walletpassword").empty()) cfg.wallet_password = val("-walletpassword");
        else if (a == "-createwallet") create_wallet = true;
        else { fprintf(stderr, "unknown option %s (see -help)\n", argv[i]); return 1; }
    }
    if (cfg.net == Network::Regtest) { cfg.p2p.dht = false; cfg.p2p.upnp = false; }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int mine = cfg.mine_threads;
    if (create_wallet) cfg.mine_threads = 0; // start mining after the wallet exists
    Node node(cfg);
    std::string err;
    if (!node.start(&err)) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    if (create_wallet && !node.wallet_loaded() && !node.has_wallet_file()) {
        std::string words = mnemonic_generate();
        if (!node.create_wallet(words, "", cfg.wallet_password, false, &err)) { fprintf(stderr, "wallet: %s\n", err.c_str()); return 1; }
        printf("\n==================== NEW WALLET ====================\n"
               "Seed words (write them down, keep them secret):\n\n  %s\n\n"
               "Receive address: %s\n"
               "====================================================\n\n",
               words.c_str(), node.wallet()->address_string(node.wallet()->issued_keys().front()->addr).c_str());
        if (mine > 0 && !node.start_mining(mine, cfg.mine_address, &err)) fprintf(stderr, "mining: %s\n", err.c_str());
    } else if (create_wallet && mine > 0) {
        node.start_mining(mine, cfg.mine_address, &err);
    }

    HttpRpcServer rpc(node, rpcport ? rpcport : node.params().rpc_port);
    if (!rpc.start(&err)) logf("RPC disabled: %s", err.c_str());

    auto last = std::chrono::steady_clock::now();
    while (!g_stop && !node.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (std::chrono::steady_clock::now() - last > std::chrono::seconds(60)) {
            last = std::chrono::steady_clock::now();
            ChainStats s;
            { std::lock_guard l(node.chain().mu); s = node.chain().stats(); }
            logf("status: height %lld/%lld, peers %zu, mempool %zu, hashrate %.0f H/s", (long long)s.height,
                 (long long)s.header_height, node.p2p() ? node.p2p()->peer_count() : 0, node.mempool().size(), node.miner().hashrate());
        }
    }
    rpc.stop();
    node.stop();
    return 0;
}
