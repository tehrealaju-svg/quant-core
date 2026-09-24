// Bech32m (BIP-350) encoding used for Quant addresses: qnt1... (mainnet), tqnt1... (testnet).
#pragma once
#include <string>

#include "util/types.h"

namespace quant {

std::string bech32m_encode(const std::string& hrp, const Bytes& data8);
// Returns false on bad checksum / charset / hrp mismatch.
bool bech32m_decode(const std::string& s, std::string& hrp_out, Bytes& data8_out);

} // namespace quant
