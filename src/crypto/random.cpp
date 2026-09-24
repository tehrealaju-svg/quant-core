// OS randomness + the PQClean `randombytes` hook. Wallet key derivation temporarily installs a
// deterministic BLAKE3 stream on the current thread so the same seed words always rebuild the
// same Falcon / SPHINCS+ keys on every device.
#include "crypto/random.h"

#include <stdexcept>

#include <blake3.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__) && !defined(__ANDROID__)
#include <sys/random.h>
#endif
#endif

namespace quant {

void os_random(uint8_t* out, size_t n) {
#ifdef _WIN32
    if (BCryptGenRandom(nullptr, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("BCryptGenRandom failed");
#else
    size_t got = 0;
#if defined(__linux__) && !defined(__ANDROID__)
    while (got < n) {
        ssize_t r = getrandom(out + got, n - got, 0);
        if (r <= 0) break;
        got += size_t(r);
    }
#endif
    if (got < n) {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) throw std::runtime_error("no /dev/urandom");
        while (got < n) {
            ssize_t r = read(fd, out + got, n - got);
            if (r <= 0) { close(fd); throw std::runtime_error("urandom read failed"); }
            got += size_t(r);
        }
        close(fd);
    }
#endif
}

Hash256 random_hash() { Hash256 h; os_random(h.data(), 32); return h; }
uint64_t random_u64() { uint64_t v; os_random((uint8_t*)&v, 8); return v; }

namespace {
struct DetStream {
    bool active = false;
    blake3_hasher h;
    uint64_t offset = 0;
};
thread_local DetStream g_det;
} // namespace

DeterministicRandom::DeterministicRandom(const uint8_t* seed, size_t n) {
    g_det.active = true;
    blake3_hasher_init_derive_key(&g_det.h, "Quant v1 deterministic keygen stream");
    blake3_hasher_update(&g_det.h, seed, n);
    g_det.offset = 0;
}
DeterministicRandom::~DeterministicRandom() { g_det.active = false; }

} // namespace quant

extern "C" int PQCLEAN_randombytes(uint8_t* output, size_t n) {
    if (quant::g_det.active) {
        blake3_hasher_finalize_seek(&quant::g_det.h, quant::g_det.offset, output, n);
        quant::g_det.offset += n;
        return 0;
    }
    quant::os_random(output, n);
    return 0;
}
