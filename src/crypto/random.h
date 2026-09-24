#pragma once
#include "util/types.h"

namespace quant {

void os_random(uint8_t* out, size_t n);
Hash256 random_hash();
uint64_t random_u64();

// RAII: while alive, PQClean's randombytes() on this thread returns a BLAKE3 stream seeded
// from `seed` instead of OS randomness (used only for deterministic wallet key generation).
class DeterministicRandom {
public:
    DeterministicRandom(const uint8_t* seed, size_t n);
    ~DeterministicRandom();
    DeterministicRandom(const DeterministicRandom&) = delete;
    DeterministicRandom& operator=(const DeterministicRandom&) = delete;
};

} // namespace quant
