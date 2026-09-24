// Peer-to-peer engine for full nodes: discovery (saved peers, BitTorrent DHT, LAN broadcast,
// manual addnode), header-first sync, block download, tx relay, and light-wallet serving.
// All peer state is owned by one event-loop thread; other threads talk to it via queues.
#pragma once
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "chain/mempool.h"
#include "net/dht.h"
#include "net/protocol.h"
#include "net/upnp.h"

namespace quant {

struct P2POptions {
    bool listen = true;
    uint16_t port = 0;               // 0 = network default
    bool dht = true, lan = true, upnp = true;
    std::vector<std::string> addnodes;
    bool connect_only = false;       // only connect to addnodes (testing)
    int max_outbound = 8;
    int max_inbound = 48;
    std::string datadir;
    std::string agent = "quant:0.1.0";
};

struct PeerInfo {
    uint64_t id;
    std::string addr;
    bool inbound;
    bool light;
    std::string agent;
    int64_t height;
    int64_t connected_secs;
    double ping_ms;
    uint64_t bytes_in, bytes_out;
    int inflight;
};

struct NetStats {
    uint64_t bytes_in = 0, bytes_out = 0;
    int outbound = 0, inbound = 0;
    size_t known_addrs = 0;
    std::string dht_status, upnp_status, lan_status;
    std::string external_addr;
    bool listening = false;
};

class P2P {
public:
    P2P(Chainstate& cs, Mempool& mp, P2POptions opt);
    ~P2P();

    bool start(std::string* err);
    void stop();

    void broadcast_tx(const Transaction& tx);   // after it's in our mempool
    void add_node(const std::string& hostport);
    void disconnect(uint64_t peer_id);
    std::vector<PeerInfo> peers() const;
    NetStats stats() const;
    size_t peer_count() const { return peer_count_; }

private:
    struct Peer;
    struct AddrInfo { int64_t last_ok = 0, last_try = 0; int attempts = 0; bool manual = false; };

    void loop();
    void accept_inbound();
    void connect_to(const NetAddr& a, bool manual);
    void on_connected(Peer& p);
    void read_peer(Peer& p);
    void flush_peer(Peer& p);
    void send(Peer& p, Cmd c, const Bytes& payload);
    void handle(Peer& p, Cmd c, const Bytes& payload);
    void misbehave(Peer& p, const std::string& why, bool ban = true);
    void maintain(int64_t now);
    void request_blocks(int64_t now);
    void send_getheaders(Peer& p, bool from_best_header);
    void process_queues();
    void lan_tick(int64_t now);
    void lan_read();
    void add_addr(const NetAddr& a, bool manual = false);
    void load_addrs();
    void save_addrs();
    void publish_info();
    Bytes build_utxo_reply(const Bytes& req);
    void learned_external(const NetAddr& a);

    Chainstate& cs_;
    Mempool& mp_;
    P2POptions opt_;
    const ChainParams& p_;
    uint64_t nonce_;
    std::atomic<bool> running_{false};
    std::thread th_;

    sock_t listen_ = BAD_SOCK, lan_ = BAD_SOCK;
    std::unique_ptr<Dht> dht_;
    std::unique_ptr<PortMapper> upnp_;
    std::vector<std::unique_ptr<Peer>> peers_;
    uint64_t next_peer_id_ = 1;
    std::map<NetAddr, AddrInfo> addrs_;
    std::map<uint32_t, int64_t> banned_; // ip -> until (seconds)
    std::map<Hash256, std::pair<uint64_t, int64_t>> inflight_; // block -> (peer, since ms)
    std::set<std::pair<Hash256, uint64_t>> no_witness_;       // (block, peer) peer couldn't give witness
    std::map<NetAddr, int> external_votes_;
    NetAddr external_;
    int64_t last_lan_ = 0, last_save_ = 0, last_announce_height_ = -1;

    // cross-thread queues
    mutable std::mutex q_mu_;
    std::deque<Transaction> q_tx_;
    std::deque<Hash256> q_relay_;
    std::deque<std::string> q_addnode_;
    std::deque<uint64_t> q_disconnect_;
    bool q_tip_ = false;

    // published snapshot
    mutable std::mutex info_mu_;
    std::vector<PeerInfo> info_;
    NetStats stats_;
    std::atomic<uint64_t> bytes_in_{0}, bytes_out_{0};
    std::atomic<size_t> peer_count_{0};
};

} // namespace quant
