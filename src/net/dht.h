// Minimal BitTorrent Mainline DHT (BEP 5) client used purely for peer discovery.
// Every Quant node announces itself under a network-specific 20-byte key; any new node can
// look that key up on the public DHT (millions of nodes, owned by no one) and find peers
// without any Quant-specific server.
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "net/socket.h"

namespace quant {

struct BVal; // bencode value

class Dht {
public:
    Dht(const uint8_t infohash[20], uint16_t udp_port, uint16_t announce_port, const std::string& state_path);
    ~Dht();

    bool start(std::string* err);
    sock_t fd() const { return sock_; }
    void on_readable();
    void tick(int64_t now_ms);
    void save();

    std::function<void(const NetAddr&)> on_peer;  // a Quant node was found
    std::function<void(const NetAddr&)> on_my_ip; // a DHT node told us our public address (BEP 42)

    bool announce = true; // light wallets only search, they don't announce themselves
    size_t node_count() const { return nodes_.size(); }
    size_t peers_found() const { return found_.size(); }
    int64_t last_announce_ms() const { return last_announce_; }
    std::string status() const;

private:
    struct Node { std::string id; NetAddr addr; int64_t last_seen = 0; int fails = 0; };
    struct LookupNode { std::string id; NetAddr addr; bool queried = false, responded = false; std::string token; };

    void send_query(const NetAddr& to, const std::string& q, const std::map<std::string, std::string>& args, bool lookup);
    void handle(const BVal& msg, const NetAddr& from);
    void add_node(const std::string& id, const NetAddr& a);
    void start_lookup();
    void step_lookup();
    void finish_lookup();
    void bootstrap();
    std::string token_for(const NetAddr& a) const;
    std::vector<Node> closest(const std::string& target, size_t n) const;

    std::string infohash_, my_id_;
    uint16_t port_, announce_port_;
    std::string state_path_;
    sock_t sock_ = BAD_SOCK;
    std::map<std::string, Node> nodes_;     // by id
    std::map<std::string, LookupNode> lookup_; // by id
    bool lookup_active_ = false;
    int64_t lookup_started_ = 0, last_lookup_ = 0, last_announce_ = 0, last_bootstrap_ = 0;
    uint16_t next_tid_ = 1;
    std::map<std::string, bool> pending_; // tid -> is lookup query
    std::set<NetAddr> found_;
    std::vector<NetAddr> stored_peers_;     // other Quant nodes that announced to us
    std::string secret_;
};

} // namespace quant
