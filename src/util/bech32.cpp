#include "util/bech32.h"

#include <cctype>
#include <cstring>

namespace quant {

static const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

static uint32_t polymod(const std::vector<uint8_t>& v) {
    uint32_t c = 1;
    for (uint8_t x : v) {
        uint8_t c0 = uint8_t(c >> 25);
        c = ((c & 0x1ffffff) << 5) ^ x;
        if (c0 & 1) c ^= 0x3b6a57b2;
        if (c0 & 2) c ^= 0x26508e6d;
        if (c0 & 4) c ^= 0x1ea119fa;
        if (c0 & 8) c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

static std::vector<uint8_t> hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> r;
    for (char c : hrp) r.push_back(uint8_t(c) >> 5);
    r.push_back(0);
    for (char c : hrp) r.push_back(uint8_t(c) & 31);
    return r;
}

static bool convert_bits(const Bytes& in, int from, int to, bool pad, Bytes& out) {
    uint32_t acc = 0; int bits = 0; uint32_t maxv = (1u << to) - 1;
    for (uint8_t v : in) {
        if (v >> from) return false;
        acc = (acc << from) | v; bits += from;
        while (bits >= to) { bits -= to; out.push_back(uint8_t((acc >> bits) & maxv)); }
    }
    if (pad) { if (bits) out.push_back(uint8_t((acc << (to - bits)) & maxv)); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) return false;
    return true;
}

std::string bech32m_encode(const std::string& hrp, const Bytes& data8) {
    Bytes d5;
    convert_bits(data8, 8, 5, true, d5);
    auto v = hrp_expand(hrp);
    v.insert(v.end(), d5.begin(), d5.end());
    v.insert(v.end(), 6, 0);
    uint32_t mod = polymod(v) ^ BECH32M_CONST;
    std::string s = hrp + "1";
    for (uint8_t x : d5) s += CHARSET[x];
    for (int i = 0; i < 6; i++) s += CHARSET[(mod >> (5 * (5 - i))) & 31];
    return s;
}

bool bech32m_decode(const std::string& in, std::string& hrp_out, Bytes& data8_out) {
    bool lower = false, upper = false;
    for (char c : in) { if (c < 33 || c > 126) return false; if (islower((unsigned char)c)) lower = true; if (isupper((unsigned char)c)) upper = true; }
    if (lower && upper) return false;
    std::string s = in;
    for (auto& c : s) c = char(tolower((unsigned char)c));
    size_t pos = s.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > s.size() || s.size() > 120) return false;
    std::string hrp = s.substr(0, pos);
    Bytes d5;
    for (size_t i = pos + 1; i < s.size(); i++) {
        const char* p = strchr(CHARSET, s[i]);
        if (!p) return false;
        d5.push_back(uint8_t(p - CHARSET));
    }
    auto v = hrp_expand(hrp);
    v.insert(v.end(), d5.begin(), d5.end());
    if (polymod(v) != BECH32M_CONST) return false;
    d5.resize(d5.size() - 6);
    Bytes d8;
    if (!convert_bits(d5, 5, 8, false, d8)) return false;
    hrp_out = hrp;
    data8_out = std::move(d8);
    return true;
}

} // namespace quant
