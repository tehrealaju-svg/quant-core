#include "crypto/sig.h"

#include <stdexcept>

#include "crypto/hash.h"
#include "crypto/random.h"

extern "C" {
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

namespace quant {

Hash256 address_hash(const Bytes& pk) { return blake3_tagged(ctx::ADDRESS, pk); }
Hash256 KeyPair::address_hash() const { return quant::address_hash(pk); }

KeyPair keypair_from_seed(const Hash256& seed) {
    KeyPair kp;
    kp.pk.resize(FALCON_PK_BYTES);
    kp.sk.resize(FALCON_SK_BYTES);
    uint8_t fseed[64];
    blake3_xof("Quant v2 falcon key seed", seed.data(), 32, fseed, sizeof fseed);
    DeterministicRandom det(fseed, sizeof fseed);
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(kp.pk.data(), kp.sk.data()) != 0)
        throw std::runtime_error("falcon keygen failed");
    return kp;
}

Bytes falcon_sign(const Bytes& sk, const Hash256& msg) {
    if (sk.size() != FALCON_SK_BYTES) throw std::runtime_error("bad falcon sk");
    Bytes sig(FALCON_SIG_MAX);
    size_t len = 0;
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig.data(), &len, msg.data(), 32, sk.data()) != 0)
        throw std::runtime_error("falcon sign failed");
    sig.resize(len);
    return sig;
}

bool falcon_verify(const Bytes& pk, const Bytes& sig, const Hash256& msg) {
    if (pk.size() != FALCON_PK_BYTES || sig.empty() || sig.size() > FALCON_SIG_MAX) return false;
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig.data(), sig.size(), msg.data(), 32, pk.data()) == 0;
}

} // namespace quant
