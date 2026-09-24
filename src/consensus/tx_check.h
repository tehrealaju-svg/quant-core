// Transaction rules shared by block validation and the mempool.
#pragma once
#include <string>

#include "primitives/transaction.h"

namespace quant {

struct Coin {
    TxOut out;
    uint64_t height = 0;
    bool coinbase = false;
};

struct TxResult {
    bool ok = true;
    std::string reason;
    Amount fee = 0;
    static TxResult fail(std::string r) { TxResult t; t.ok = false; t.reason = std::move(r); return t; }
};

// Context-free checks: shape, limits, dust, duplicate inputs, witness count.
TxResult check_tx_basic(const Transaction& tx, bool expect_witness);

// Full check against the coins being spent (coins[i] is the coin for tx.ins[i]).
// `height` is the height of the block that would contain the tx.
TxResult check_tx_inputs(const Transaction& tx, const std::vector<Coin>& coins, uint64_t height,
                         const Hash256& genesis, bool verify_sigs);

// Signature check only.
bool verify_witness(const Transaction& tx, const std::vector<Coin>& coins, const Hash256& genesis, std::string* why);

} // namespace quant
