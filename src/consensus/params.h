#pragma once
#include <string>

#include "primitives/block.h"
#include "util/u256.h"

namespace quant {

enum class Network { Main, Test, Regtest };

struct ChainParams {
    Network net;
    std::string name;           // "main", "test", "regtest"
    std::string hrp;            // bech32 address prefix
    uint8_t magic[4];
    uint16_t p2p_port;
    uint16_t rpc_port;
    U256 pow_limit;             // easiest allowed target
    uint32_t genesis_bits;      // starting difficulty
    bool no_retarget = false;   // regtest: fixed difficulty
    bool launched = true;       // mainnet stays off until Ambrose sets the launch constants
    uint64_t genesis_time;
    std::string genesis_message;
    Block genesis;
    Hash256 genesis_hash;
    uint8_t dht_infohash[20];   // key used to find peers on the BitTorrent DHT
    uint16_t lan_port;          // UDP port for LAN discovery broadcasts

    std::string address_hrp() const { return hrp; }
};

const ChainParams& params_for(Network n);
Network network_from_name(const std::string& s, bool* ok = nullptr);
Block make_genesis(uint64_t time, uint32_t bits, const std::string& msg);

// Addresses
std::string encode_address(const ChainParams& p, uint8_t ver, const Hash256& addr);
bool decode_address(const ChainParams& p, const std::string& s, uint8_t& ver, Hash256& addr);

} // namespace quant
