#include "wallet/mnemonic.h"

#include <cctype>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "crypto/hash.h"
#include "crypto/random.h"

namespace quant {

#include "wallet/bip39_words.inc"

static int word_index(const std::string& w) {
    static const std::unordered_map<std::string, int> m = [] {
        std::unordered_map<std::string, int> r;
        for (int i = 0; i < 2048; i++) r[BIP39_WORDS[i]] = i;
        return r;
    }();
    auto it = m.find(w);
    return it == m.end() ? -1 : it->second;
}

std::string mnemonic_normalize(const std::string& s) {
    std::istringstream is(s);
    std::string w, out;
    while (is >> w) {
        for (auto& c : w) c = char(tolower((unsigned char)c));
        if (!out.empty()) out += ' ';
        out += w;
    }
    return out;
}

static std::string encode(const uint8_t ent[32]) {
    Hash256 h = sha256(ent, 32);
    // 256 bits entropy + 8 bits checksum = 264 bits = 24 x 11
    uint8_t bits[33];
    std::memcpy(bits, ent, 32);
    bits[32] = h.b[0];
    std::string out;
    for (int i = 0; i < 24; i++) {
        int idx = 0;
        for (int j = 0; j < 11; j++) {
            int bit = i * 11 + j;
            idx = (idx << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1);
        }
        if (i) out += ' ';
        out += BIP39_WORDS[idx];
    }
    return out;
}

std::string mnemonic_generate() {
    uint8_t ent[32];
    os_random(ent, 32);
    return encode(ent);
}

bool mnemonic_valid(const std::string& words) {
    std::istringstream is(mnemonic_normalize(words));
    std::vector<int> idx;
    std::string w;
    while (is >> w) {
        int i = word_index(w);
        if (i < 0) return false;
        idx.push_back(i);
    }
    if (idx.size() != 24) return false;
    uint8_t bits[33] = {};
    for (int i = 0; i < 24; i++)
        for (int j = 0; j < 11; j++) {
            int bit = i * 11 + j;
            if ((idx[i] >> (10 - j)) & 1) bits[bit / 8] |= uint8_t(1 << (7 - bit % 8));
        }
    return sha256(bits, 32).b[0] == bits[32];
}

Hash256 mnemonic_to_master(const std::string& words, const std::string& passphrase) {
    std::string s = mnemonic_normalize(words) + '\0' + passphrase;
    Hash256 h;
    blake3_xof("Quant v1 wallet master seed", (const uint8_t*)s.data(), s.size(), h.data(), 32);
    // Key stretching so a leaked phrase-with-passphrase is harder to brute force.
    for (int i = 0; i < 100000; i++) h = blake3_tagged("Quant v1 wallet stretch", h.data(), 32);
    return h;
}

} // namespace quant
