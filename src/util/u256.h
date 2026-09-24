// Minimal 256-bit unsigned arithmetic for proof-of-work targets and chain work.
#pragma once
#include "util/types.h"

namespace quant {

struct U256 {
    uint64_t w[4]{}; // little-endian limbs: w[0] least significant

    U256() = default;
    explicit U256(uint64_t v) { w[0] = v; }
    static U256 from_hash(const Hash256& h);   // big-endian bytes -> number
    Hash256 to_hash() const;
    static U256 from_compact(uint32_t bits, bool* negative = nullptr, bool* overflow = nullptr);
    uint32_t to_compact() const;

    bool is_zero() const { return !(w[0] | w[1] | w[2] | w[3]); }
    int bits() const;
    double to_double() const;
    std::string hex() const { return to_hash().hex(); }

    friend int cmp(const U256& a, const U256& b) {
        for (int i = 3; i >= 0; i--) if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1;
        return 0;
    }
    friend bool operator<(const U256& a, const U256& b) { return cmp(a, b) < 0; }
    friend bool operator>(const U256& a, const U256& b) { return cmp(a, b) > 0; }
    friend bool operator<=(const U256& a, const U256& b) { return cmp(a, b) <= 0; }
    friend bool operator>=(const U256& a, const U256& b) { return cmp(a, b) >= 0; }
    friend bool operator==(const U256& a, const U256& b) { return cmp(a, b) == 0; }

    U256& operator+=(const U256& o);
    U256& operator-=(const U256& o);
    U256& operator<<=(unsigned s);
    U256& operator>>=(unsigned s);
    U256& mul64(uint64_t m);     // truncating
    U256& div64(uint64_t d);
    friend U256 operator+(U256 a, const U256& b) { return a += b; }
    friend U256 operator-(U256 a, const U256& b) { return a -= b; }
    friend U256 operator<<(U256 a, unsigned s) { return a <<= s; }
    friend U256 operator>>(U256 a, unsigned s) { return a >>= s; }
    friend U256 operator/(const U256& a, const U256& b);
    U256 operator~() const { U256 r; for (int i = 0; i < 4; i++) r.w[i] = ~w[i]; return r; }
};

// Expected number of hashes to find a block with this target: 2^256 / (target + 1).
U256 work_from_target(const U256& target);

} // namespace quant
