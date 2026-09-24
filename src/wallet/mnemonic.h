// 24-word seed phrases (BIP-39 wordlist + checksum). The same words restore the same wallet
// on the PC client, quantd, and the Termux wallet.
#pragma once
#include <string>

#include "util/types.h"

namespace quant {

std::string mnemonic_generate();                      // 24 words, 256-bit entropy
bool mnemonic_valid(const std::string& words);        // wordlist + checksum
std::string mnemonic_normalize(const std::string& s); // lowercase, single spaces
// Master wallet secret from words + optional extra passphrase ("25th word").
Hash256 mnemonic_to_master(const std::string& words, const std::string& passphrase);

} // namespace quant
