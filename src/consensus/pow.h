#pragma once
#include <functional>

#include "consensus/params.h"

namespace quant {

bool check_pow(const Hash256& hash, uint32_t bits, const ChainParams& p);

// Minimal view of past headers needed by the difficulty algorithm.
struct HeaderInfo { uint64_t time; uint32_t bits; };

// LWMA-1 (zawy12): linearly weighted moving average over the last LWMA_WINDOW solve times.
// `prev(i)` returns the header i blocks back from the tip (0 = tip). `tip_height` is the
// height of the tip; the result is the required bits for block tip_height + 1.
uint32_t next_bits(int64_t tip_height, const std::function<HeaderInfo(int)>& prev, const ChainParams& p);

} // namespace quant
