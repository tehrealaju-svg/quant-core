// Thin cross-platform socket layer (Winsock / POSIX incl. Android/Termux).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
constexpr sock_t BAD_SOCK = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
using sock_t = int;
constexpr sock_t BAD_SOCK = -1;
#endif

namespace quant {

struct NetAddr {
    uint32_t ip = 0;   // IPv4, host byte order
    uint16_t port = 0;
    bool operator==(const NetAddr& o) const { return ip == o.ip && port == o.port; }
    bool operator<(const NetAddr& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }
    std::string str() const;
    std::string ip_str() const;
    bool routable() const;  // public internet address
    bool is_local() const;  // loopback / LAN
    sockaddr_in to_sockaddr() const;
    static NetAddr from_sockaddr(const sockaddr_in& a);
    static bool parse(const std::string& s, uint16_t default_port, NetAddr& out); // "1.2.3.4:5" or "host:5"
};

void net_init();
void sock_close(sock_t s);
bool sock_nonblocking(sock_t s);
int sock_error();
bool sock_would_block(int err);
std::string sock_error_str(int err);
std::vector<NetAddr> resolve(const std::string& host, uint16_t port);

sock_t tcp_listen(uint16_t port, bool any_interface, std::string* err);
sock_t tcp_connect_nb(const NetAddr& a);        // non-blocking connect started
sock_t udp_bind(uint16_t port, bool broadcast, std::string* err);

#ifdef _WIN32
using pollfd_t = WSAPOLLFD;
inline int sock_poll(pollfd_t* f, size_t n, int ms) { return WSAPoll(f, ULONG(n), ms); }
#else
using pollfd_t = pollfd;
inline int sock_poll(pollfd_t* f, size_t n, int ms) { return ::poll(f, nfds_t(n), ms); }
#endif

} // namespace quant
