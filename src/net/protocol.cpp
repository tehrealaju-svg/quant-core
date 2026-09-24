#include "net/protocol.h"

#include "crypto/hash.h"

namespace quant {

const char* cmd_name(Cmd c) {
    switch (c) {
    case Cmd::Version: return "version"; case Cmd::Verack: return "verack"; case Cmd::Ping: return "ping";
    case Cmd::Pong: return "pong"; case Cmd::GetAddr: return "getaddr"; case Cmd::Addr: return "addr";
    case Cmd::Inv: return "inv"; case Cmd::GetData: return "getdata"; case Cmd::NotFound: return "notfound";
    case Cmd::GetHeaders: return "getheaders"; case Cmd::Headers: return "headers"; case Cmd::BlockMsg: return "block";
    case Cmd::TxMsg: return "tx"; case Cmd::GetUtxos: return "getutxos"; case Cmd::Utxos: return "utxos";
    case Cmd::Reject: return "reject";
    }
    return "?";
}

Bytes VersionMsg::encode() const {
    Writer w;
    w.u32le(version); w.u64le(services); w.u64le(nonce); w.u64le(uint64_t(height));
    w.u32le(listen_port); w.str(agent); w.hash(genesis);
    write_addr(w, your_addr);
    return w.buf;
}

VersionMsg VersionMsg::decode(Reader& r) {
    VersionMsg v;
    v.version = r.u32le(); v.services = r.u64le(); v.nonce = r.u64le(); v.height = int64_t(r.u64le());
    v.listen_port = uint16_t(r.u32le()); v.agent = r.str(256); v.genesis = r.hash();
    v.your_addr = read_addr(r);
    return v;
}

void UtxoProof::write(Writer& w) const {
    w.hash(op.txid); w.varint(op.n);
    w.varint(coin.out.value); w.u8(coin.out.addr_ver); w.hash(coin.out.addr);
    w.varint(coin.height); w.u8(coin.coinbase);
    w.hash(block);
    w.bytes(tx_core);
    w.varint(tx_index); w.varint(tx_count);
    w.varint(merkle.size());
    for (auto& h : merkle) w.hash(h);
}

UtxoProof UtxoProof::read(Reader& r) {
    UtxoProof u;
    u.op.txid = r.hash(); u.op.n = uint32_t(r.varint());
    u.coin.out.value = r.varint(); u.coin.out.addr_ver = r.u8(); u.coin.out.addr = r.hash();
    u.coin.height = r.varint(); u.coin.coinbase = r.u8() != 0;
    u.block = r.hash();
    u.tx_core = r.bytes(MAX_MESSAGE);
    u.tx_index = uint32_t(r.varint()); u.tx_count = uint32_t(r.varint());
    size_t n = r.varint_max(64);
    for (size_t i = 0; i < n; i++) u.merkle.push_back(r.hash());
    return u;
}

void write_addr(Writer& w, const NetAddr& a) { w.raw(a.ip.data(), 16); w.u8(uint8_t(a.port >> 8)); w.u8(uint8_t(a.port)); }
NetAddr read_addr(Reader& r) { NetAddr a; r.raw(a.ip.data(), 16); a.port = uint16_t(r.u8() << 8); a.port |= r.u8(); return a; }

Bytes frame_message(const ChainParams& p, Cmd cmd, const Bytes& payload) {
    Hash256 c = blake3_tagged(ctx::NETCHECK, payload);
    Writer w;
    w.raw(p.magic, 4);
    w.u8(uint8_t(cmd));
    w.u32le(uint32_t(payload.size()));
    w.raw(c.data(), 4);
    w.raw(payload);
    return w.buf;
}

int FrameReader::next(Cmd& cmd, Bytes& payload, std::string* err) {
    if (buf_.size() < FRAME_HEADER) return 0;
    if (std::memcmp(buf_.data(), p_.magic, 4) != 0) { if (err) *err = "bad magic (wrong network?)"; return -1; }
    uint32_t len = uint32_t(buf_[5]) | uint32_t(buf_[6]) << 8 | uint32_t(buf_[7]) << 16 | uint32_t(buf_[8]) << 24;
    if (len > MAX_MESSAGE) { if (err) *err = "message too large"; return -1; }
    if (buf_.size() < FRAME_HEADER + len) return 0;
    Hash256 c = blake3_tagged(ctx::NETCHECK, buf_.data() + FRAME_HEADER, len);
    if (std::memcmp(c.data(), buf_.data() + 9, 4) != 0) { if (err) *err = "bad checksum"; return -1; }
    cmd = Cmd(buf_[4]);
    payload.assign(buf_.begin() + FRAME_HEADER, buf_.begin() + FRAME_HEADER + len);
    buf_.erase(buf_.begin(), buf_.begin() + FRAME_HEADER + len);
    return 1;
}

} // namespace quant
