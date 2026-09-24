#include "net/socket.h"

#include <algorithm>
#include <cstring>
#include <mutex>

#ifdef _WIN32
#else
#include <csignal>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#endif

namespace quant {

static const uint8_t V4_PREFIX[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

NetAddr NetAddr::v4(uint32_t ip4, uint16_t port) {
    NetAddr a;
    std::memcpy(a.ip.data(), V4_PREFIX, 12);
    a.ip[12] = uint8_t(ip4 >> 24); a.ip[13] = uint8_t(ip4 >> 16); a.ip[14] = uint8_t(ip4 >> 8); a.ip[15] = uint8_t(ip4);
    a.port = port;
    return a;
}
bool NetAddr::is_v4() const { return std::memcmp(ip.data(), V4_PREFIX, 12) == 0; }
uint32_t NetAddr::v4_ip() const { return uint32_t(ip[12]) << 24 | uint32_t(ip[13]) << 16 | uint32_t(ip[14]) << 8 | ip[15]; }
bool NetAddr::is_zero() const {
    if (is_v4()) return v4_ip() == 0;
    for (auto b : ip) if (b) return false;
    return true;
}

std::string NetAddr::ip_str() const {
    char b[INET6_ADDRSTRLEN] = {0};
    if (is_v4()) {
        snprintf(b, sizeof b, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
        return b;
    }
    in6_addr a6;
    std::memcpy(&a6, ip.data(), 16);
    inet_ntop(AF_INET6, &a6, b, sizeof b);
    return b;
}
std::string NetAddr::str() const { return is_v4() ? ip_str() + ":" + std::to_string(port) : "[" + ip_str() + "]:" + std::to_string(port); }

bool NetAddr::is_local() const {
    if (is_v4()) {
        uint8_t a = ip[12], b = ip[13];
        return a == 127 || a == 10 || (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
    }
    static const uint8_t loop[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (std::memcmp(ip.data(), loop, 16) == 0) return true;
    if (ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
    if ((ip[0] & 0xfe) == 0xfc) return true;                   // fc00::/7 unique local
    return false;
}

bool NetAddr::routable() const {
    if (port == 0 || is_local()) return false;
    if (is_v4()) {
        uint8_t a = ip[12], b = ip[13];
        if (a == 0 || a >= 224) return false;
        if (a == 100 && b >= 64 && b <= 127) return false; // CGNAT
        return true;
    }
    if ((ip[0] & 0xe0) != 0x20) return false;                      // global unicast is 2000::/3
    if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8) return false; // documentation
    return true;
}

socklen_t NetAddr::to_sockaddr(int family, sockaddr_storage& out) const {
    std::memset(&out, 0, sizeof out);
    if (family == AF_INET) {
        if (!is_v4()) return 0;
        auto* s = (sockaddr_in*)&out;
        s->sin_family = AF_INET;
        s->sin_addr.s_addr = htonl(v4_ip());
        s->sin_port = htons(port);
        return sizeof(sockaddr_in);
    }
    auto* s = (sockaddr_in6*)&out;
    s->sin6_family = AF_INET6;
    std::memcpy(&s->sin6_addr, ip.data(), 16); // IPv4-mapped works on dual-stack sockets
    s->sin6_port = htons(port);
    return sizeof(sockaddr_in6);
}

NetAddr NetAddr::from_sockaddr(const sockaddr* a) {
    NetAddr n;
    if (a->sa_family == AF_INET) {
        auto* s = (const sockaddr_in*)a;
        n = v4(ntohl(s->sin_addr.s_addr), ntohs(s->sin_port));
    } else if (a->sa_family == AF_INET6) {
        auto* s = (const sockaddr_in6*)a;
        std::memcpy(n.ip.data(), &s->sin6_addr, 16);
        n.port = ntohs(s->sin6_port);
    }
    return n;
}

bool NetAddr::parse(const std::string& s, uint16_t default_port, NetAddr& out) {
    std::string host = s;
    uint16_t port = default_port;
    if (!s.empty() && s[0] == '[') {
        size_t e = s.find(']');
        if (e == std::string::npos) return false;
        host = s.substr(1, e - 1);
        if (e + 1 < s.size()) {
            if (s[e + 1] != ':') return false;
            try { port = uint16_t(std::stoi(s.substr(e + 2))); } catch (...) { return false; }
        }
    } else if (std::count(s.begin(), s.end(), ':') == 1) {
        size_t c = s.find(':');
        host = s.substr(0, c);
        try { port = uint16_t(std::stoi(s.substr(c + 1))); } catch (...) { return false; }
    }
    in_addr ia{};
    in6_addr i6{};
    if (inet_pton(AF_INET, host.c_str(), &ia) == 1) { out = v4(ntohl(ia.s_addr), port); return true; }
    if (inet_pton(AF_INET6, host.c_str(), &i6) == 1) { std::memcpy(out.ip.data(), &i6, 16); out.port = port; return true; }
    auto r = resolve(host, port);
    if (r.empty()) return false;
    out = r[0];
    return true;
}

static bool g_v6 = false;

void net_init() {
    static std::once_flag once;
    std::call_once(once, [] {
#ifdef _WIN32
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
#else
        signal(SIGPIPE, SIG_IGN);
#endif
        sock_t t = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        g_v6 = t != BAD_SOCK;
        sock_close(t);
    });
}
bool net_ipv6_available() { net_init(); return g_v6; }

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

std::vector<NetAddr> resolve(const std::string& host, uint16_t port, int family) {
    net_init();
    std::vector<NetAddr> out;
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return out;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET && p->ai_family != AF_INET6) continue;
        NetAddr a = NetAddr::from_sockaddr(p->ai_addr);
        a.port = port;
        out.push_back(a);
    }
    freeaddrinfo(res);
    return out;
}

sock_t tcp_listen(uint16_t port, bool any, std::string* err) {
    net_init();
    sock_t s = BAD_SOCK;
    if (g_v6) {
        s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (s != BAD_SOCK) {
            int off = 0, one = 1;
            setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof off); // accept IPv4 too
#ifndef _WIN32
            setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one);
#else
            (void)one;
#endif
            sockaddr_in6 a{};
            a.sin6_family = AF_INET6;
            a.sin6_addr = any ? in6addr_any : in6addr_loopback;
            a.sin6_port = htons(port);
            if (!any) {
                // loopback-only listeners (RPC) stay IPv4 so 127.0.0.1 clients work everywhere
                sock_close(s);
                s = BAD_SOCK;
            } else if (bind(s, (sockaddr*)&a, sizeof a) != 0 || listen(s, 64) != 0) {
                sock_close(s);
                s = BAD_SOCK;
            }
        }
    }
    if (s == BAD_SOCK) {
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    }
    sock_nonblocking(s);
    return s;
}

sock_t tcp_connect_nb(const NetAddr& addr) {
    net_init();
    int fam = addr.is_v4() ? AF_INET : AF_INET6;
    if (fam == AF_INET6 && !g_v6) return BAD_SOCK;
    sock_t s = socket(fam, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) return BAD_SOCK;
    sock_nonblocking(s);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, 1 /*TCP_NODELAY*/, (const char*)&one, sizeof one);
    sockaddr_storage ss;
    socklen_t len = addr.to_sockaddr(fam, ss);
    if (connect(s, (sockaddr*)&ss, len) != 0 && !sock_would_block(sock_error())) {
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

sock_t udp_bind6(uint16_t port, std::string* err) {
    net_init();
    if (!g_v6) { if (err) *err = "IPv6 not available"; return BAD_SOCK; }
    sock_t s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == BAD_SOCK) { if (err) *err = "socket(AF_INET6)"; return BAD_SOCK; }
    int one = 1;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&one, sizeof one);
    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    a.sin6_addr = in6addr_any;
    a.sin6_port = htons(port);
    if (bind(s, (sockaddr*)&a, sizeof a) != 0) {
        if (err) *err = "udp6 port " + std::to_string(port) + " busy";
        sock_close(s);
        return BAD_SOCK;
    }
    sock_nonblocking(s);
    return s;
}

int udp_send(sock_t s, int family, const NetAddr& to, const void* data, size_t len) {
    sockaddr_storage ss;
    socklen_t sl = to.to_sockaddr(family, ss);
    if (!sl) return -1;
    return int(sendto(s, (const char*)data, int(len), 0, (sockaddr*)&ss, sl));
}

} // namespace quant
