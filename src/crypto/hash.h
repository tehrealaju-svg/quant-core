// BLAKE3 hashing with domain separation. Every distinct use of the hash gets its own
// context string, so a hash computed for one purpose can never be replayed as another.
#pragma once
#include "util/types.h"

namespace quant {

Hash256 blake3(const uint8_t* p, size_t n);
inline Hash256 blake3(const Bytes& b) { return blake3(b.data(), b.size()); }
// Hash with a domain-separation context (BLAKE3 derive_key mode keys a hasher with the context).
Hash256 blake3_tagged(const char* context, const uint8_t* p, size_t n);
inline Hash256 blake3_tagged(const char* ctx, const Bytes& b) { return blake3_tagged(ctx, b.data(), b.size()); }
// Keyed hash (MAC / PRF).
Hash256 blake3_keyed(const Hash256& key, const uint8_t* p, size_t n);
// Extendable output.
void blake3_xof(const char* context, const uint8_t* in, size_t n, uint8_t* out, size_t outlen);

Hash256 sha256(const uint8_t* p, size_t n); // only for BIP39 mnemonic checksums

// Context strings (never change these — they are consensus).
namespace ctx {
constexpr const char* HEADER   = "Quant v1 block header";      // unused: PoW hashes raw header
constexpr const char* TXID     = "Quant v1 txid";
constexpr const char* WTXID    = "Quant v1 witness";
constexpr const char* MERKLE   = "Quant v1 merkle node";
constexpr const char* SIGHASH  = "Quant v1 sighash";
constexpr const char* ADDRESS  = "Quant v1 address";
constexpr const char* PUBKEY   = "Quant v1 pubkey";
constexpr const char* NETCHECK = "Quant v1 p2p checksum";
} // namespace ctx

} // namespace quant
