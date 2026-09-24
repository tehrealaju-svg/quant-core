// Post-quantum signatures.
//   Primary: Falcon-512 (NIST FN-DSA) — small lattice signatures (~655 B) and keys (897 B).
//   Backup:  SPHINCS+-SHAKE-128s-simple — hash-based, relies only on hash security. Its
//            public key is committed inside every address, so coins can still be moved with
//            it if lattice cryptography is ever broken (after a soft fork disables Falcon).
#pragma once
#include "util/types.h"

namespace quant {

constexpr size_t FALCON_PK_BYTES = 897;
constexpr size_t FALCON_SK_BYTES = 1281;
constexpr size_t FALCON_SIG_MAX = 752;
constexpr size_t SPHINCS_PK_BYTES = 32;
constexpr size_t SPHINCS_SK_BYTES = 64;
constexpr size_t SPHINCS_SIG_BYTES = 7856;
constexpr size_t SPHINCS_SEED_BYTES = 48;

struct KeyPair {
    Bytes falcon_pk, falcon_sk;
    Bytes sphincs_pk, sphincs_sk;

    Hash256 falcon_pkhash() const;
    Hash256 sphincs_pkhash() const;
    Hash256 address_hash() const;
};

// Deterministically derive a full key pair from a 32-byte seed.
KeyPair keypair_from_seed(const Hash256& seed);

Hash256 pubkey_hash(const Bytes& pk);
Hash256 address_hash(const Hash256& falcon_pkhash, const Hash256& sphincs_pkhash);

Bytes falcon_sign(const Bytes& sk, const Hash256& msg);
bool falcon_verify(const Bytes& pk, const Bytes& sig, const Hash256& msg);
Bytes sphincs_sign(const Bytes& sk, const Hash256& msg);
bool sphincs_verify(const Bytes& pk, const Bytes& sig, const Hash256& msg);

} // namespace quant
