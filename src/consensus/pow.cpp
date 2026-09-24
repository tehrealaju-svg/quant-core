#include "consensus/pow.h"

#include <algorithm>

#include "consensus/limits.h"

namespace quant {

bool check_pow(const Hash256& hash, uint32_t bits, const ChainParams& p) {
    bool neg = false, ovf = false;
    U256 target = U256::from_compact(bits, &neg, &ovf);
    if (neg || ovf || target.is_zero() || target > p.pow_limit) return false;
    return U256::from_hash(hash) <= target;
}

uint32_t next_bits(int64_t tip_height, const std::function<HeaderInfo(int)>& prev, const ChainParams& p) {
    if (p.no_retarget) return p.genesis_bits;
    const int64_t T = TARGET_SPACING;
    int64_t N = std::min<int64_t>(LWMA_WINDOW, tip_height); // number of solve times available
    if (N < 3) return prev(0).bits;

    const int64_t k = N * (N + 1) * T / 2;
    int64_t weighted = 0;
    U256 sum_target;
    // oldest -> newest, weight 1..N
    for (int64_t j = 1; j <= N; j++) {
        HeaderInfo cur = prev(int(N - j));
        HeaderInfo before = prev(int(N - j + 1));
        int64_t st = int64_t(cur.time) - int64_t(before.time);
        st = std::clamp<int64_t>(st, -6 * T, 6 * T);
        weighted += st * j;
        sum_target += U256::from_compact(cur.bits);
    }
    if (weighted < k / 10) weighted = k / 10; // guard against timestamp manipulation
    // next = (sum_target / N) * weighted / k
    U256 next = sum_target;
    next.div64(uint64_t(N) * uint64_t(k));
    next.mul64(uint64_t(weighted));
    if (next > p.pow_limit || next.is_zero()) next = p.pow_limit;
    return next.to_compact();
}

} // namespace quant
