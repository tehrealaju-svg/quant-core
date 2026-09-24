#include "crypto/sig.h"

#include <stdexcept>

#include "crypto/hash.h"
#include "crypto/random.h"

// Declared by hand: both PQClean schemes ship a header called api.h.
extern "C" {
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t* pk, uint8_t* sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);
int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
}

namespace quant {

Hash256 pubkey_hash(const Bytes& pk) { return blake3_tagged(ctx::PUBKEY, pk); }

Hash256 address_hash(const Hash256& fh, const Hash256& sh) {
    uint8_t buf[64];
    std::memcpy(buf, fh.data(), 32);
    std::memcpy(buf + 32, sh.data(), 32);
    return blake3_tagged(ctx::ADDRESS, buf, 64);
}

Hash256 KeyPair::falcon_pkhash() const { return pubkey_hash(falcon_pk); }
Hash256 KeyPair::sphincs_pkhash() const { return pubkey_hash(sphincs_pk); }
Hash256 KeyPair::address_hash() const { return quant::address_hash(falcon_pkhash(), sphincs_pkhash()); }

KeyPair keypair_from_seed(const Hash256& seed) {
    KeyPair kp;
    kp.falcon_pk.resize(FALCON_PK_BYTES);
    kp.falcon_sk.resize(FALCON_SK_BYTES);
    {
        uint8_t fseed[64];
        blake3_xof("Quant v1 falcon key seed", seed.data(), 32, fseed, sizeof fseed);
        DeterministicRandom det(fseed, sizeof fseed);
        if (PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(kp.falcon_pk.data(), kp.falcon_sk.data()) != 0)
            throw std::runtime_error("falcon keygen failed");
    }
    uint8_t sseed[SPHINCS_SEED_BYTES];
    blake3_xof("Quant v1 sphincs key seed", seed.data(), 32, sseed, sizeof sseed);
    kp.sphincs_pk.resize(SPHINCS_PK_BYTES);
    kp.sphincs_sk.resize(SPHINCS_SK_BYTES);
    if (PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_seed_keypair(kp.sphincs_pk.data(), kp.sphincs_sk.data(), sseed) != 0)
        throw std::runtime_error("sphincs keygen failed");
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

Bytes sphincs_sign(const Bytes& sk, const Hash256& msg) {
    if (sk.size() != SPHINCS_SK_BYTES) throw std::runtime_error("bad sphincs sk");
    Bytes sig(SPHINCS_SIG_BYTES);
    size_t len = 0;
    if (PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig.data(), &len, msg.data(), 32, sk.data()) != 0)
        throw std::runtime_error("sphincs sign failed");
    sig.resize(len);
    return sig;
}

bool sphincs_verify(const Bytes& pk, const Bytes& sig, const Hash256& msg) {
    if (pk.size() != SPHINCS_PK_BYTES || sig.size() != SPHINCS_SIG_BYTES) return false;
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig.data(), sig.size(), msg.data(), 32, pk.data()) == 0;
}

} // namespace quant
