// Quant P2P wire protocol.
//   frame = magic[4] | cmd u8 | len u32le | checksum[4] | payload[len]
#pragma once
#include "consensus/params.h"
#include "consensus/tx_check.h"
#include "net/socket.h"

namespace quant {

constexpr uint32_t PROTOCOL_VERSION = 1;
constexpr size_t MAX_MESSAGE = 4 * 1024 * 1024;
constexpr size_t FRAME_HEADER = 13;
constexpr size_t MAX_HEADERS_PER_MSG = 2000;

enum class Cmd : uint8_t {
    Version = 1, Verack = 2, Ping = 3, Pong = 4, GetAddr = 5, Addr = 6,
    Inv = 7, GetData = 8, NotFound = 9, GetHeaders = 10, Headers = 11,
    BlockMsg = 12, TxMsg = 13, GetUtxos = 14, Utxos = 15, Reject = 16,
};
const char* cmd_name(Cmd c);

enum : uint64_t { SERVICE_FULL = 1, SERVICE_LIGHT_SERVE = 2, SERVICE_ARCHIVE = 4 };
enum : uint8_t { INV_TX = 1, INV_BLOCK = 2 };

struct VersionMsg {
    uint32_t version = PROTOCOL_VERSION;
    uint64_t services = 0;
    uint64_t nonce = 0;
    int64_t height = 0;
    uint16_t listen_port = 0;
    std::string agent;
    Hash256 genesis;
    NetAddr your_addr; // how we see the peer (lets NAT'd nodes learn their public IP)
    Bytes encode() const;
    static VersionMsg decode(Reader& r);
};

struct InvItem { uint8_t type; Hash256 hash; };

// A confirmed coin plus proof that its transaction is inside a block (for light wallets).
struct UtxoProof {
    OutPoint op;
    Coin coin;
    Hash256 block;
    Bytes tx_core;              // the transaction without signatures
    uint32_t tx_index = 0, tx_count = 0;
    std::vector<Hash256> merkle;
    void write(Writer& w) const;
    static UtxoProof read(Reader& r);
};

Bytes frame_message(const ChainParams& p, Cmd cmd, const Bytes& payload);

// Incremental frame parser.
class FrameReader {
public:
    explicit FrameReader(const ChainParams& p) : p_(p) {}
    void feed(const uint8_t* d, size_t n) { buf_.insert(buf_.end(), d, d + n); }
    // Returns 1 with a message, 0 if more data needed, -1 on protocol error.
    int next(Cmd& cmd, Bytes& payload, std::string* err);
    size_t buffered() const { return buf_.size(); }
private:
    const ChainParams& p_;
    Bytes buf_;
};

} // namespace quant
