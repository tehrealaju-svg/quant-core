#include "node/httprpc.h"

#include <chrono>
#include <fstream>

#include "crypto/random.h"
#include "util/log.h"

namespace quant {

static bool recv_http(sock_t c, std::string& body, std::string& headers, int timeout_ms) {
    std::string buf;
    char tmp[8192];
    auto start = std::chrono::steady_clock::now();
    size_t hdr_end = std::string::npos, need = 0;
    for (;;) {
        pollfd_t f{};
        f.fd = c;
        f.events = POLLIN;
        if (sock_poll(&f, 1, 200) > 0) {
            int n = int(recv(c, tmp, sizeof tmp, 0));
            if (n <= 0) return false;
            buf.append(tmp, size_t(n));
            if (buf.size() > 16 * 1024 * 1024) return false;
        }
        if (hdr_end == std::string::npos) {
            hdr_end = buf.find("\r\n\r\n");
            if (hdr_end != std::string::npos) {
                headers = buf.substr(0, hdr_end);
                std::string lower = headers;
                for (auto& ch : lower) ch = char(tolower((unsigned char)ch));
                size_t cl = lower.find("content-length:");
                need = cl == std::string::npos ? 0 : size_t(std::stoul(lower.substr(cl + 15)));
            }
        }
        if (hdr_end != std::string::npos && buf.size() >= hdr_end + 4 + need) {
            body = buf.substr(hdr_end + 4, need);
            return true;
        }
        if (std::chrono::steady_clock::now() - start > std::chrono::milliseconds(timeout_ms)) return false;
    }
}

static void send_all(sock_t c, const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        int n = int(::send(c, s.data() + off, int(s.size() - off), 0));
        if (n > 0) { off += size_t(n); continue; }
        if (n < 0 && sock_would_block(sock_error())) { std::this_thread::sleep_for(std::chrono::milliseconds(2)); continue; }
        return;
    }
}

bool HttpRpcServer::start(std::string* err) {
    token_ = random_hash().hex();
    std::ofstream(cookie_path(node_.dir())) << token_;
    sock_ = tcp_listen(port_, false, err);
    if (sock_ == BAD_SOCK) return false;
    running_ = true;
    th_ = std::thread([this] { run(); });
    logf("RPC listening on 127.0.0.1:%u", port_);
    return true;
}

void HttpRpcServer::stop() {
    if (!running_) return;
    running_ = false;
    if (th_.joinable()) th_.join();
    sock_close(sock_);
    std::remove(cookie_path(node_.dir()).c_str());
}

void HttpRpcServer::run() {
    while (running_) {
        pollfd_t f{};
        f.fd = sock_;
        f.events = POLLIN;
        if (sock_poll(&f, 1, 200) <= 0) continue;
        sock_t c = accept(sock_, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        serve(c);
        sock_close(c);
    }
}

void HttpRpcServer::serve(sock_t c) {
    std::string body, headers;
    if (!recv_http(c, body, headers, 10000)) return;
    auto reply = [&](int code, const std::string& b) {
        std::string s = "HTTP/1.1 " + std::to_string(code) + (code == 200 ? " OK" : " Error") +
                        "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + std::to_string(b.size()) +
                        "\r\n\r\n" + b;
        send_all(c, s);
    };
    if (headers.find("Bearer " + token_) == std::string::npos) { reply(401, R"({"error":"unauthorized"})"); return; }
    json req, resp;
    try {
        req = json::parse(body);
    } catch (...) {
        reply(400, R"({"error":"bad json"})");
        return;
    }
    resp["id"] = req.value("id", json(nullptr));
    try {
        resp["result"] = node_.rpc(req.value("method", ""), req.value("params", json::array()));
        resp["error"] = nullptr;
    } catch (const std::exception& e) {
        resp["result"] = nullptr;
        resp["error"] = e.what();
    }
    reply(200, resp.dump());
}

bool http_rpc_call(uint16_t port, const std::string& token, const std::string& method, const json& params,
                   json& result, std::string* err) {
    net_init();
    sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(s, (sockaddr*)&a, sizeof a) != 0) {
        if (err) *err = "cannot connect to quantd on port " + std::to_string(port) + " (is it running?)";
        sock_close(s);
        return false;
    }
    json req = {{"method", method}, {"params", params}, {"id", 1}};
    std::string b = req.dump();
    std::string msg = "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + token +
                      "\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b;
    send_all(s, msg);
    std::string body, headers;
    bool ok = recv_http(s, body, headers, 600000);
    sock_close(s);
    if (!ok) { if (err) *err = "no response from quantd"; return false; }
    try {
        json r = json::parse(body);
        if (r.contains("error") && !r["error"].is_null()) { if (err) *err = r["error"].is_string() ? r["error"].get<std::string>() : r["error"].dump(); return false; }
        result = r["result"];
        return true;
    } catch (...) {
        if (err) *err = "bad response: " + body.substr(0, 200);
        return false;
    }
}

} // namespace quant
