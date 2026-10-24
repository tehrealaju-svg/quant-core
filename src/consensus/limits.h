// Hard consensus limits. Changing any of these is a fork.
#pragma once
#include <cstdint>

#include "util/types.h"

namespace quant {

constexpr size_t MAX_TX_INPUTS = 10'000;
constexpr size_t MAX_TX_OUTPUTS = 10'000;
constexpr size_t MAX_TX_OPS = 16;
constexpr size_t MAX_COINBASE_EXTRA = 100;
constexpr size_t MAX_BLOCK_SIZE = 1'000'000;      // bytes incl. witness
constexpr size_t MAX_TX_SIZE = 400'000;

// ---- emission: smooth decay to a permanent tail (Monero-style, no halvings)
//   reward = max(TAIL_SUBSIDY, (EMISSION_CURVE - issued) >> EMISSION_SPEED)
//   Starts at ~17.5 QNT, falls smoothly, reaches the 3.5 QNT tail after ~6.5 years (~14.7M QNT) and
//   stays there forever so miners (and late users) are always paid.
constexpr Amount EMISSION_CURVE = 18'400'000ULL * COIN;
constexpr int EMISSION_SPEED = 20;
constexpr Amount TAIL_SUBSIDY = 35 * COIN / 10;   // 3.5 QNT per block forever
constexpr Amount MAX_MONEY = 1'000'000'000ULL * COIN; // sanity bound on any single amount / sum

constexpr Amount DUST_LIMIT = 10'000;             // 0.000001 QNT: smallest non-coinbase QNT output

// ---- tokens / pools
constexpr size_t MAX_TICKER = 10;
constexpr size_t MAX_TOKEN_NAME = 32;
constexpr size_t MAX_TOKEN_URI = 120;
constexpr uint8_t MAX_TOKEN_DECIMALS = 10;
constexpr Amount MAX_TOKEN_SUPPLY = 10'000'000'000'000'000'000ULL; // 1e19 base units
constexpr Amount MIN_LIQUIDITY = 1000;            // pool shares locked forever at pool creation
constexpr uint64_t POOL_FEE_BPS = 30;             // 0.3% of each swap stays in the pool (all to liquidity providers)

// ---- timing / difficulty
constexpr int64_t TARGET_SPACING = 120;           // seconds
constexpr int LWMA_WINDOW = 60;                   // blocks (2 hours)
constexpr int64_t MAX_FUTURE_DRIFT = 360;         // seconds a header may be ahead of now
constexpr int MEDIAN_TIME_SPAN = 11;
constexpr int COINBASE_MATURITY = 100;

// ---- size reduction
constexpr int PRUNE_DEPTH = 5040;                 // ~1 week: witnesses/undo kept this deep
constexpr int MAX_REORG_DEPTH = PRUNE_DEPTH;
// Every SNAPSHOT_INTERVAL blocks the full state (coins, tokens, pools) is hashed; the block
// SNAPSHOT_DELAY later commits that hash in its header. New nodes download a committed
// snapshot instead of the whole history.
// (Interval / delay are per network: ChainParams::snapshot_interval / snapshot_delay;
// main + test use 10,080 (~2 weeks) / 100, regtest uses 50 / 5 so tests can reach them.)

// Policy (not consensus): relay fee.
constexpr Amount MIN_RELAY_FEE_PER_KB = 100'000;  // 0.00001 QNT per 1000 bytes

// Subsidy of the block after `issued` units have been created by earlier subsidies.
inline Amount subsidy_after(Amount issued) {
    Amount r = issued >= EMISSION_CURVE ? 0 : (EMISSION_CURVE - issued) >> EMISSION_SPEED;
    return r < TAIL_SUBSIDY ? TAIL_SUBSIDY : r;
}
// Subsidy at `height` (genesis pays nothing) and total issued through `height`.
Amount block_subsidy(uint64_t height);
Amount issued_through(uint64_t height);

} // namespace quant
