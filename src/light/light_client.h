// SPV light wallet client (used by the Termux phone wallet).
// Keeps only block headers (120 B each), verifies proof-of-work and difficulty itself, and asks
// full nodes for its coins, each delivered with a Merkle proof against a verified header.
// Keys never leave the device. Peers are found via saved peers, LAN broadcast, the
// BitTorrent DHT, or a manual address. No servers.
#pragma once
#include <functional>
#include <memory>
#include <string>

#include "net/protocol.h"
#include "wallet/wallet.h"

namespace quant {

class LightClient {
public:
    LightClient(const ChainParams& p, const std::string& dir);
    ~LightClient();

    std::function<void(const std::string&)> on_status; // progress messages

    // Find and connect to up to `want` full nodes. Returns number connected.
    int connect(const std::vector<std::string>& addnodes, int want = 3, int timeout_s = 25);
    void disconnect_all();
    size_t peer_count() const { return peers_.size(); }
    std::vector<std::string> peer_names() const;

    bool sync_headers(std::string* err);
    int64_t height() const { return int64_t(headers_.size()) - 1; }
    const BlockHeader& tip() const { return headers_.back(); }

    // Fetch + verify coins for the wallet's addresses; updates the wallet.
    bool refresh_wallet(Wallet& w, std::string* err);
    // Broadcast; returns false with the node's reason if rejected.
    bool broadcast(const Transaction& tx, std::string* err);

private:
    struct Peer;
    bool load_headers();
    bool append_header(const BlockHeader& h, std::string* why);
    bool exchange(Peer& p, Cmd send_cmd, const Bytes& payload, Cmd want, Bytes& reply, int timeout_ms);
    bool send_msg(Peer& p, Cmd c, const Bytes& payload);
    bool recv_msg(Peer& p, Cmd& c, Bytes& payload, int timeout_ms);
    bool handshake(Peer& p, int timeout_ms);
    std::vector<NetAddr> discover(int timeout_s, size_t enough);
    std::vector<Hash256> locator() const;

    const ChainParams& p_;
    std::string dir_;
    std::vector<BlockHeader> headers_;
    std::vector<Hash256> hashes_;
    std::vector<std::unique_ptr<Peer>> peers_;
    uint64_t nonce_;
};

} // namespace quant
