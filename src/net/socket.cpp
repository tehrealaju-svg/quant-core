#include "net/socket.h"

#include <cstring>
#include <mutex>

#ifdef _WIN32
#else
#include <errno.h>
#include <csignal>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#endif

namespace quant {

std::string NetAddr::ip_str() const {
    char b[32];
    snprintf(b, sizeof b, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return b;
}
std::string NetAddr::str() const { return ip_str() + ":" + std::to_string(port); }

bool NetAddr::is_local() const {
    uint8_t a = ip >> 24, b = (ip >> 16) & 255;
    return a == 127 || a == 10 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
}

bool NetAddr::routable() const {
    uint8_t a = ip >> 24, b = (ip >> 16) & 255;
    if (ip == 0 || a == 0 || a >= 224 || is_local()) return false;
    if (a == 100 && b >= 64 && b <= 127) return false; // CGNAT
    return port != 0;
}

sockaddr_in NetAddr::to_sockaddr() const {
    sockaddr_in s{};
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl(ip);
    s.sin_port = htons(port);
    return s;
}

NetAddr NetAddr::from_sockaddr(const sockaddr_in& a) {
    NetAddr n;
    n.ip = ntohl(a.sin_addr.s_addr);
    n.port = ntohs(a.sin_port);
    return n;
}

bool NetAddr::parse(const std::string& s, uint16_t default_port, NetAddr& out) {
    std::string host = s;
    uint16_t port = default_port;
    size_t c = s.rfind(':');
    if (c != std::string::npos) {
        host = s.substr(0, c);
        try { port = uint16_t(std::stoi(s.substr(c + 1))); } catch (...) { return false; }
    }
    in_addr ia{};
    if (inet_pton(AF_INET, host.c_str(), &ia) == 1) {
        out.ip = ntohl(ia.s_addr);
        out.port = port;
        return true;
    }
    auto r = resolve(host, port);
    if (r.empty()) return false;
    out = r[0];
    return true;
}

void net_init() {
#ifdef _WIN32
    static std::once_flag once;
    std::call_once(once, [] { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); });
#else
    signal(SIGPIPE, SIG_IGN);
#endif
}

void sock_close(sock_t s) {
    if (s == BAD_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

bool sock_nonblocking(sock_t s) {
#ifdef _WIN32
    u_long one = 1;
    return ioctlsocket(s, FIONBIO, &one) == 0;
#else
    int f = fcntl(s, F_GETFL, 0);
    return fcntl(s, F_SETFL, f | O_NONBLOCK) == 0;
#endif
}

int sock_error() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

bool sock_would_block(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#else
    return e == EWOULDBLOCK || e == EAGAIN || e == EINPROGRESS;
#endif
}

std::string sock_error_str(int e) { return "socket error " + std::to_string(e); }

std::vector<NetAddr> resolve(const std::string& host, uint16_t port) {
    net_init();
    std::vector<NetAddr> out;
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return out;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        NetAddr a = NetAddr::from_sockaddr(*(sockaddr_in*)p->ai_addr);
        a.port = port;
        out.push_back(a);
    }
    freeaddrinfo(res);
    return out;
}

sock_t tcp_listen(uint16_t port, bool any, std::string* err) {
    net_init();
    sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) { if (err) *err = "socket()"; return BAD_SOCK; }
    int one = 1;
#ifndef _WIN32
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
#else
    (void)one;
#endif
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(any ? INADDR_ANY : INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof a) != 0 || listen(s, 64) != 0) {
        if (err) *err = "port " + std::to_string(port) + " is busy (another node running?)";
        sock_close(s);
        return BAD_SOCK;
    }
    sock_nonblocking(s);
    return s;
}

sock_t tcp_connect_nb(const NetAddr& addr) {
    net_init();
    sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) return BAD_SOCK;
    sock_nonblocking(s);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, 1 /*TCP_NODELAY*/, (const char*)&one, sizeof one);
    sockaddr_in a = addr.to_sockaddr();
    if (connect(s, (sockaddr*)&a, sizeof a) != 0 && !sock_would_block(sock_error())) {
        sock_close(s);
        return BAD_SOCK;
    }
    return s;
}

sock_t udp_bind(uint16_t port, bool broadcast, std::string* err) {
    net_init();
    sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == BAD_SOCK) { if (err) *err = "socket()"; return BAD_SOCK; }
    int one = 1;
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
#ifdef SO_REUSEPORT
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char*)&one, sizeof one);
#endif
    if (broadcast) setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof a) != 0) {
        if (err) *err = "udp port " + std::to_string(port) + " busy";
        sock_close(s);
        return BAD_SOCK;
    }
    sock_nonblocking(s);
    return s;
}

} // namespace quant
