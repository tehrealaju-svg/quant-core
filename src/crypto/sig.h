// Post-quantum signatures: Falcon-512 (NIST FN-DSA) — small lattice signatures (~655 B) and
// keys (897 B). An address is the hash of a Falcon public key; the key itself only appears
// on-chain when the address spends, and is pruned with the signature later.
#pragma once
#include "util/types.h"

namespace quant {

constexpr size_t FALCON_PK_BYTES = 897;
constexpr size_t FALCON_SK_BYTES = 1281;
constexpr size_t FALCON_SIG_MAX = 752;

struct KeyPair {
    Bytes pk, sk;
    Hash256 address_hash() const;
};

// Deterministically derive a key pair from a 32-byte seed.
KeyPair keypair_from_seed(const Hash256& seed);

Hash256 address_hash(const Bytes& pk);

Bytes falcon_sign(const Bytes& sk, const Hash256& msg);
bool falcon_verify(const Bytes& pk, const Bytes& sig, const Hash256& msg);

} // namespace quant
