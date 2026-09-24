#include "util/u256.h"

#include <cmath>

namespace quant {

U256 U256::from_hash(const Hash256& h) {
    U256 r;
    for (int i = 0; i < 32; i++) r.w[(31 - i) / 8] |= uint64_t(h.b[i]) << (8 * ((31 - i) % 8));
    return r;
}

Hash256 U256::to_hash() const {
    Hash256 h;
    for (int i = 0; i < 32; i++) h.b[i] = uint8_t(w[(31 - i) / 8] >> (8 * ((31 - i) % 8)));
    return h;
}

int U256::bits() const {
    for (int i = 3; i >= 0; i--)
        if (w[i]) return i * 64 + 64 - __builtin_clzll(w[i]);
    return 0;
}

double U256::to_double() const {
    double r = 0;
    for (int i = 3; i >= 0; i--) r = r * 18446744073709551616.0 + double(w[i]);
    return r;
}

U256& U256::operator+=(const U256& o) {
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) { c += (unsigned __int128)w[i] + o.w[i]; w[i] = uint64_t(c); c >>= 64; }
    return *this;
}

U256& U256::operator-=(const U256& o) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t a = w[i], b = o.w[i];
        uint64_t d = a - b - borrow;
        borrow = (a < b) || (a - b < borrow) ? 1 : 0;
        w[i] = d;
    }
    return *this;
}

U256& U256::operator<<=(unsigned s) {
    if (s >= 256) { *this = U256(); return *this; }
    U256 r;
    unsigned limb = s / 64, bit = s % 64;
    for (int i = 3; i >= 0; i--) {
        int src = i - int(limb);
        if (src < 0) continue;
        r.w[i] = w[src] << bit;
        if (bit && src > 0) r.w[i] |= w[src - 1] >> (64 - bit);
    }
    *this = r;
    return *this;
}

U256& U256::operator>>=(unsigned s) {
    if (s >= 256) { *this = U256(); return *this; }
    U256 r;
    unsigned limb = s / 64, bit = s % 64;
    for (int i = 0; i < 4; i++) {
        int src = i + int(limb);
        if (src > 3) continue;
        r.w[i] = w[src] >> bit;
        if (bit && src < 3) r.w[i] |= w[src + 1] << (64 - bit);
    }
    *this = r;
    return *this;
}

U256& U256::mul64(uint64_t m) {
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) { c += (unsigned __int128)w[i] * m; w[i] = uint64_t(c); c >>= 64; }
    return *this;
}

U256& U256::div64(uint64_t d) {
    unsigned __int128 rem = 0;
    for (int i = 3; i >= 0; i--) {
        unsigned __int128 cur = (rem << 64) | w[i];
        w[i] = uint64_t(cur / d);
        rem = cur % d;
    }
    return *this;
}

U256 operator/(const U256& a, const U256& b) {
    if (b.is_zero()) return U256();
    U256 q, r;
    for (int i = a.bits() - 1; i >= 0; i--) {
        r <<= 1;
        r.w[0] |= (a.w[i / 64] >> (i % 64)) & 1;
        if (r >= b) { r -= b; q.w[i / 64] |= 1ULL << (i % 64); }
    }
    return q;
}

// Bitcoin-style compact encoding: 1 byte exponent + 3 byte mantissa.
U256 U256::from_compact(uint32_t bits, bool* negative, bool* overflow) {
    int size = int(bits >> 24);
    uint32_t word = bits & 0x007fffff;
    U256 r;
    if (size <= 3) { word >>= 8 * (3 - size); r = U256(word); }
    else { r = U256(word); r <<= unsigned(8 * (size - 3)); }
    if (negative) *negative = word != 0 && (bits & 0x00800000) != 0;
    if (overflow) *overflow = word != 0 && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
    return r;
}

uint32_t U256::to_compact() const {
    int size = (bits() + 7) / 8;
    uint32_t compact;
    if (size <= 3) compact = uint32_t(w[0] << (8 * (3 - size)));
    else compact = uint32_t((*this >> unsigned(8 * (size - 3))).w[0]);
    if (compact & 0x00800000) { compact >>= 8; size++; }
    return compact | (uint32_t(size) << 24);
}

U256 work_from_target(const U256& target) {
    // 2^256 / (t+1) == (~t / (t+1)) + 1
    U256 one(1);
    return (~target / (target + one)) + one;
}

} // namespace quant
