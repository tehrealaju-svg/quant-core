#include "consensus/params.h"

#include <memory>
#include <mutex>

#include "consensus/limits.h"
#include "crypto/hash.h"
#include "util/bech32.h"

namespace quant {

// ============================================================================
//  MAINNET LAUNCH CONSTANTS — set these when you're ready to launch (see LAUNCH.md).
//  Until MAINNET_GENESIS_TIME is non-zero, quantd refuses to run on mainnet.
// ============================================================================
static constexpr uint64_t MAINNET_GENESIS_TIME = 0;
static const char* MAINNET_GENESIS_MESSAGE = "Quant: post-quantum money for everyone";

Amount block_subsidy(uint64_t height) {
    if (height == 0) return 0;
    uint64_t era = (height - 1) / HALVING_INTERVAL;
    if (era >= 63) return 0;
    Amount r = INITIAL_SUBSIDY >> era;
    return r < MIN_SUBSIDY ? 0 : r;
}

Block make_genesis(uint64_t time, uint32_t bits, const std::string& msg) {
    Block b;
    Transaction cb;
    cb.lock_height = 0;
    cb.extra.assign(msg.begin(), msg.end());
    if (cb.extra.size() > MAX_COINBASE_EXTRA) cb.extra.resize(MAX_COINBASE_EXTRA);
    // No outputs: nobody owns the genesis reward (no premine).
    b.txs.push_back(cb);
    b.header.version = 1;
    b.header.time = time;
    b.header.bits = bits;
    b.header.nonce = 0;
    b.header.merkle_root = b.compute_merkle_root();
    b.header.witness_root = b.compute_witness_root();
    return b;
}

static void finish(ChainParams& p) {
    p.genesis = make_genesis(p.genesis_time, p.genesis_bits, p.genesis_message);
    p.genesis_hash = p.genesis.header.hash();
    std::string key = "Quant DHT v1 " + p.name + " " + p.genesis_hash.hex();
    Hash256 h = blake3((const uint8_t*)key.data(), key.size());
    std::memcpy(p.dht_infohash, h.data(), 20);
}

static std::unique_ptr<ChainParams> build(Network n) {
    auto p = std::make_unique<ChainParams>();
    p->net = n;
    switch (n) {
    case Network::Main:
        p->name = "main"; p->hrp = "qnt";
        p->magic[0] = 0x51; p->magic[1] = 0x4e; p->magic[2] = 0x54; p->magic[3] = 0xa1;
        p->p2p_port = 7337; p->rpc_port = 7338; p->lan_port = 7339;
        p->pow_limit = (U256(1) << 236) - U256(1);
        p->genesis_bits = (U256(1) << 226).to_compact();
        p->genesis_time = MAINNET_GENESIS_TIME ? MAINNET_GENESIS_TIME : 1790000000;
        p->launched = MAINNET_GENESIS_TIME != 0;
        p->genesis_message = MAINNET_GENESIS_MESSAGE;
        break;
    case Network::Test:
        p->name = "test"; p->hrp = "tqnt";
        p->magic[0] = 0x51; p->magic[1] = 0x4e; p->magic[2] = 0x54; p->magic[3] = 0x7e;
        p->p2p_port = 17337; p->rpc_port = 17338; p->lan_port = 17339;
        p->pow_limit = (U256(1) << 240) - U256(1);
        p->genesis_bits = (U256(1) << 230).to_compact();
        p->genesis_time = 1790121600; // 2026-09-23
        p->genesis_message = "Quant testnet 2026-09-23";
        break;
    case Network::Regtest:
        p->name = "regtest"; p->hrp = "rqnt";
        p->magic[0] = 0x51; p->magic[1] = 0x4e; p->magic[2] = 0x54; p->magic[3] = 0x0f;
        p->p2p_port = 27337; p->rpc_port = 27338; p->lan_port = 27339;
        p->pow_limit = (U256(1) << 255) - U256(1);
        p->genesis_bits = p->pow_limit.to_compact();
        p->no_retarget = true;
        p->genesis_time = 1790121600;
        p->genesis_message = "Quant regtest";
        break;
    }
    finish(*p);
    return p;
}

const ChainParams& params_for(Network n) {
    static std::unique_ptr<ChainParams> cache[3];
    static std::once_flag once[3];
    int i = int(n);
    std::call_once(once[i], [&] { cache[i] = build(n); });
    return *cache[i];
}

Network network_from_name(const std::string& s, bool* ok) {
    if (ok) *ok = true;
    if (s == "main" || s == "mainnet") return Network::Main;
    if (s == "test" || s == "testnet") return Network::Test;
    if (s == "regtest") return Network::Regtest;
    if (ok) *ok = false;
    return Network::Test;
}

std::string encode_address(const ChainParams& p, uint8_t ver, const Hash256& addr) {
    Bytes d;
    d.push_back(ver);
    d.insert(d.end(), addr.b.begin(), addr.b.end());
    return bech32m_encode(p.hrp, d);
}

bool decode_address(const ChainParams& p, const std::string& s, uint8_t& ver, Hash256& addr) {
    std::string hrp; Bytes d;
    if (!bech32m_decode(s, hrp, d)) return false;
    if (hrp != p.hrp || d.size() != 33) return false;
    ver = d[0];
    std::memcpy(addr.data(), d.data() + 1, 32);
    return true;
}

} // namespace quant
