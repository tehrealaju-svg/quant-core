// Hard consensus limits. Changing any of these is a fork.
#pragma once
#include <cstdint>

#include "util/types.h"

namespace quant {

constexpr size_t MAX_TX_INPUTS = 10'000;
constexpr size_t MAX_TX_OUTPUTS = 10'000;
constexpr size_t MAX_COINBASE_EXTRA = 100;
constexpr size_t MAX_BLOCK_SIZE = 1'000'000;      // bytes incl. witness
constexpr size_t MAX_TX_SIZE = 400'000;

constexpr Amount INITIAL_SUBSIDY = 50 * COIN;
constexpr uint64_t HALVING_INTERVAL = 2'102'400;   // 8 years of 2-minute blocks
constexpr Amount MIN_SUBSIDY = 125;               // rewards stop once they'd fall below this
constexpr Amount DUST_LIMIT = 10'000;             // 0.000001 QNT: smallest non-coinbase output
constexpr Amount MAX_MONEY = 210'240'000ULL * COIN;

constexpr int64_t TARGET_SPACING = 120;           // seconds
constexpr int LWMA_WINDOW = 60;                   // blocks (2 hours)
constexpr int64_t MAX_FUTURE_DRIFT = 360;         // seconds a header may be ahead of now
constexpr int MEDIAN_TIME_SPAN = 11;
constexpr int COINBASE_MATURITY = 100;
constexpr int PRUNE_DEPTH = 5040;                 // ~1 week: witnesses/undo kept this deep
constexpr int MAX_REORG_DEPTH = PRUNE_DEPTH;

// Policy (not consensus): relay fee.
constexpr Amount MIN_RELAY_FEE_PER_KB = 100'000;  // 0.00001 QNT per 1000 bytes

Amount block_subsidy(uint64_t height);

} // namespace quant
