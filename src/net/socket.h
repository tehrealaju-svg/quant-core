// Thin cross-platform socket layer (Winsock / POSIX incl. Android/Termux), IPv4 + IPv6.
// Addresses are stored as 16 bytes; IPv4 uses the IPv4-mapped form ::ffff:a.b.c.d so one type
// covers both. TCP listening is dual-stack, so a node behind IPv4 CGNAT (Starlink, mobile)
// can still accept peers over IPv6.
#pragma once
#include <array>
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
    std::array<uint8_t, 16> ip{};
    uint16_t port = 0;

    static NetAddr v4(uint32_t ip4, uint16_t port);
    bool is_v4() const;
    uint32_t v4_ip() const; // host byte order (only if is_v4)
    bool is_zero() const;
    NetAddr with_port(uint16_t p) const { NetAddr a = *this; a.port = p; return a; }
    bool operator==(const NetAddr& o) const { return ip == o.ip && port == o.port; }
    bool operator<(const NetAddr& o) const { return ip != o.ip ? ip < o.ip : port < o.port; }
    std::string str() const;     // "1.2.3.4:5" or "[2001:db8::1]:5"
    std::string ip_str() const;
    bool routable() const;       // public internet address
    bool is_local() const;       // loopback / LAN / link-local / ULA
    // Fill a sockaddr for a socket of the given family (AF_INET or AF_INET6). Returns length, 0 if impossible.
    socklen_t to_sockaddr(int family, sockaddr_storage& out) const;
    static NetAddr from_sockaddr(const sockaddr* a);
    // "1.2.3.4:5", "[v6]:5", "v6", "host:5", "host"
    static bool parse(const std::string& s, uint16_t default_port, NetAddr& out);
};

void net_init();
bool net_ipv6_available();
void sock_close(sock_t s);
bool sock_nonblocking(sock_t s);
int sock_error();
bool sock_would_block(int err);
std::string sock_error_str(int err);
// family: AF_UNSPEC (both), AF_INET or AF_INET6
std::vector<NetAddr> resolve(const std::string& host, uint16_t port, int family = AF_UNSPEC);

sock_t tcp_listen(uint16_t port, bool any_interface, std::string* err); // dual-stack when possible
sock_t tcp_connect_nb(const NetAddr& a);                                // non-blocking connect started
sock_t udp_bind(uint16_t port, bool broadcast, std::string* err);       // IPv4 UDP (LAN, v4 DHT)
sock_t udp_bind6(uint16_t port, std::string* err);                      // IPv6-only UDP (v6 DHT)
int udp_send(sock_t s, int family, const NetAddr& to, const void* data, size_t len);

#ifdef _WIN32
using pollfd_t = WSAPOLLFD;
inline int sock_poll(pollfd_t* f, size_t n, int ms) { return WSAPoll(f, ULONG(n), ms); }
#else
using pollfd_t = pollfd;
inline int sock_poll(pollfd_t* f, size_t n, int ms) { return ::poll(f, nfds_t(n), ms); }
#endif

} // namespace quant
