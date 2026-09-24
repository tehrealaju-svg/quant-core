// JSON-RPC over HTTP on localhost, authenticated with a random cookie file.
#pragma once
#include <atomic>
#include <string>
#include <thread>

#include "node/node.h"

namespace quant {

class HttpRpcServer {
public:
    HttpRpcServer(Node& node, uint16_t port) : node_(node), port_(port) {}
    ~HttpRpcServer() { stop(); }
    bool start(std::string* err);
    void stop();
    static std::string cookie_path(const std::string& node_dir) { return node_dir + "/.cookie"; }

private:
    void run();
    void serve(sock_t c);
    Node& node_;
    uint16_t port_;
    sock_t sock_ = BAD_SOCK;
    std::string token_;
    std::atomic<bool> running_{false};
    std::thread th_;
};

// Client side (quant-cli).
bool http_rpc_call(uint16_t port, const std::string& token, const std::string& method, const json& params,
                   json& result, std::string* err);

} // namespace quant
