// Compact binary serialization. Integers use canonical (minimal) LEB128 varints so every
// object has exactly one encoding — no txid malleability through encoding tricks.
#pragma once
#include <stdexcept>
#include <string>

#include "util/types.h"

namespace quant {

struct SerializeError : std::runtime_error { using std::runtime_error::runtime_error; };

class Writer {
public:
    Bytes buf;
    void u8(uint8_t v) { buf.push_back(v); }
    void u32le(uint32_t v) { for (int i = 0; i < 4; i++) buf.push_back(uint8_t(v >> (8 * i))); }
    void u64le(uint64_t v) { for (int i = 0; i < 8; i++) buf.push_back(uint8_t(v >> (8 * i))); }
    void varint(uint64_t v) {
        while (v >= 0x80) { buf.push_back(uint8_t(v | 0x80)); v >>= 7; }
        buf.push_back(uint8_t(v));
    }
    void raw(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p + n); }
    void raw(const Bytes& b) { raw(b.data(), b.size()); }
    void hash(const Hash256& h) { raw(h.data(), 32); }
    void bytes(const Bytes& b) { varint(b.size()); raw(b); }
    void str(const std::string& s) { varint(s.size()); raw((const uint8_t*)s.data(), s.size()); }
};

class Reader {
public:
    const uint8_t* p;
    size_t n, pos = 0;
    Reader(const uint8_t* data, size_t len) : p(data), n(len) {}
    explicit Reader(const Bytes& b) : p(b.data()), n(b.size()) {}

    size_t left() const { return n - pos; }
    bool empty() const { return pos == n; }
    void need(size_t k) const { if (k > n - pos) throw SerializeError("unexpected end of data"); }
    uint8_t u8() { need(1); return p[pos++]; }
    uint32_t u32le() { need(4); uint32_t v = 0; for (int i = 0; i < 4; i++) v |= uint32_t(p[pos + i]) << (8 * i); pos += 4; return v; }
    uint64_t u64le() { need(8); uint64_t v = 0; for (int i = 0; i < 8; i++) v |= uint64_t(p[pos + i]) << (8 * i); pos += 8; return v; }
    uint64_t varint() {
        uint64_t v = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            uint8_t c = u8();
            if (shift == 63 && c > 1) throw SerializeError("varint overflow");
            v |= uint64_t(c & 0x7f) << shift;
            if (!(c & 0x80)) {
                if (c == 0 && shift > 0) throw SerializeError("non-canonical varint");
                return v;
            }
        }
        throw SerializeError("varint too long");
    }
    uint64_t varint_max(uint64_t max) { uint64_t v = varint(); if (v > max) throw SerializeError("value too large"); return v; }
    void raw(uint8_t* out, size_t k) { need(k); std::memcpy(out, p + pos, k); pos += k; }
    Bytes raw(size_t k) { need(k); Bytes b(p + pos, p + pos + k); pos += k; return b; }
    Hash256 hash() { Hash256 h; raw(h.data(), 32); return h; }
    Bytes bytes(size_t max) { return raw(varint_max(max)); }
    std::string str(size_t max) { auto b = bytes(max); return std::string(b.begin(), b.end()); }
};

} // namespace quant
