// Basic fixed-size byte types, hex helpers.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace quant {

using Bytes = std::vector<uint8_t>;
using Amount = uint64_t; // base units; 1 QNT = 10^10 units

constexpr Amount COIN = 10'000'000'000ULL; // 10 decimal places

std::string hex_encode(const uint8_t* p, size_t n);
inline std::string hex_encode(const Bytes& b) { return hex_encode(b.data(), b.size()); }
std::optional<Bytes> hex_decode(std::string_view s);

// 32-byte hash. Displayed / compared as a big-endian number (byte 0 is most significant).
struct Hash256 {
    std::array<uint8_t, 32> b{};

    bool is_zero() const { for (auto x : b) if (x) return false; return true; }
    std::string hex() const { return hex_encode(b.data(), 32); }
    static std::optional<Hash256> from_hex(std::string_view s);
    uint8_t* data() { return b.data(); }
    const uint8_t* data() const { return b.data(); }
    auto operator<=>(const Hash256&) const = default;
    bool operator==(const Hash256&) const = default;
};

struct Hash256Hasher {
    size_t operator()(const Hash256& h) const noexcept {
        size_t v; std::memcpy(&v, h.b.data(), sizeof v); return v;
    }
};

// Format an amount in base units as "123.0000000001" (trailing zeros trimmed, at least 1 decimal).
std::string format_amount(Amount a);
// Parse "1.5" / "0.0000000001" / "12" into base units. Rejects > 10 decimals.
std::optional<Amount> parse_amount(std::string_view s);

int64_t now_seconds();
int64_t now_millis();

} // namespace quant
