#include "crypto/hash.h"

#include <blake3.h>

extern "C" {
#include "sha2.h"
}

namespace quant {

Hash256 blake3(const uint8_t* p, size_t n) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, p, n);
    Hash256 out;
    blake3_hasher_finalize(&h, out.data(), 32);
    return out;
}

Hash256 blake3_tagged(const char* context, const uint8_t* p, size_t n) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, context);
    blake3_hasher_update(&h, p, n);
    Hash256 out;
    blake3_hasher_finalize(&h, out.data(), 32);
    return out;
}

Hash256 blake3_keyed(const Hash256& key, const uint8_t* p, size_t n) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key.data());
    blake3_hasher_update(&h, p, n);
    Hash256 out;
    blake3_hasher_finalize(&h, out.data(), 32);
    return out;
}

void blake3_xof(const char* context, const uint8_t* in, size_t n, uint8_t* out, size_t outlen) {
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, context);
    blake3_hasher_update(&h, in, n);
    blake3_hasher_finalize(&h, out, outlen);
}

Hash256 sha256(const uint8_t* p, size_t n) {
    Hash256 out;
    ::sha256(out.data(), p, n);
    return out;
}

} // namespace quant
