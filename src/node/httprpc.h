// JSON-RPC over HTTP on localhost, authenticated with a random cookie file.
#pragma once
#include <atomic>
#include <string>
#include <thread>

#include "node/node.h"

namespace quant {

class HttpRpcServer {
public:
    // public = no cookie, CORS, read-only methods + sendrawtransaction (for websites / browser
    // wallets, exposed through a tunnel). Still binds to localhost only.
    HttpRpcServer(Node& node, uint16_t port, bool is_public = false) : node_(node), port_(port), public_(is_public) {}
    static bool public_method(const std::string& m);
    ~HttpRpcServer() { stop(); }
    bool start(std::string* err);
    void stop();
    static std::string cookie_path(const std::string& node_dir) { return node_dir + "/.cookie"; }

private:
    void run();
    void serve(sock_t c);
    Node& node_;
    uint16_t port_;
    bool public_ = false;
    std::atomic<int> active_{0};
    sock_t sock_ = BAD_SOCK;
    std::string token_;
    std::atomic<bool> running_{false};
    std::thread th_;
};

// Client side (quant-cli).
bool http_rpc_call(uint16_t port, const std::string& token, const std::string& method, const json& params,
                   json& result, std::string* err);

} // namespace quant
