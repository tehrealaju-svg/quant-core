#include "util/types.h"

#include <chrono>

namespace quant {

static const char* HEXD = "0123456789abcdef";

std::string hex_encode(const uint8_t* p, size_t n) {
    std::string s(n * 2, '0');
    for (size_t i = 0; i < n; i++) { s[2 * i] = HEXD[p[i] >> 4]; s[2 * i + 1] = HEXD[p[i] & 15]; }
    return s;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<Bytes> hex_decode(std::string_view s) {
    if (s.size() % 2) return std::nullopt;
    Bytes out(s.size() / 2);
    for (size_t i = 0; i < out.size(); i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = uint8_t(hi << 4 | lo);
    }
    return out;
}

std::optional<Hash256> Hash256::from_hex(std::string_view s) {
    auto b = hex_decode(s);
    if (!b || b->size() != 32) return std::nullopt;
    Hash256 h; std::memcpy(h.b.data(), b->data(), 32); return h;
}

std::string format_amount(Amount a) {
    std::string whole = std::to_string(a / COIN);
    std::string frac = std::to_string(a % COIN);
    frac = std::string(10 - frac.size(), '0') + frac;
    while (frac.size() > 1 && frac.back() == '0') frac.pop_back();
    return whole + "." + frac;
}

std::optional<Amount> parse_amount(std::string_view s) {
    if (s.empty() || s.size() > 32) return std::nullopt;
    size_t dot = s.find('.');
    std::string_view w = s.substr(0, dot), f = dot == std::string_view::npos ? "" : s.substr(dot + 1);
    if (w.empty() && f.empty()) return std::nullopt;
    if (f.size() > 10) return std::nullopt;
    unsigned __int128 v = 0;
    for (char c : w) { if (c < '0' || c > '9') return std::nullopt; v = v * 10 + (c - '0'); if (v > 1000000000000ULL) return std::nullopt; }
    v *= COIN;
    uint64_t fr = 0;
    for (size_t i = 0; i < 10; i++) {
        char c = i < f.size() ? f[i] : '0';
        if (c < '0' || c > '9') return std::nullopt;
        fr = fr * 10 + (c - '0');
    }
    v += fr;
    if (v > UINT64_MAX) return std::nullopt;
    return Amount(v);
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace quant
