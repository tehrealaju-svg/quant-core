// The ledger rules: how a transaction changes the state (coins, tokens, pools).
//
// State is read through StateReader (the chainstate, or another view). A LedgerView is an
// overlay that applies transactions one at a time — a failed tx leaves the view untouched —
// and can then be committed by the chainstate, or kept as the mempool's pending state.
#pragma once
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "primitives/transaction.h"

namespace quant {

struct Coin {
    TxOut out;
    uint64_t height = 0;
    bool coinbase = false;
};

struct TokenInfo {
    Hash256 id;
    std::string ticker, name, uri;
    uint8_t decimals = 0;
    Amount supply = 0;
    Hash256 create_txid;
    uint64_t height = 0;
};

struct Pool {
    Hash256 token;
    Amount qnt = 0, tok = 0;   // reserves
    Amount shares = 0;         // outstanding pool shares (incl. the MIN_LIQUIDITY locked forever)
    bool operator==(const Pool&) const = default;
};

struct TxResult {
    bool ok = true;
    std::string reason;
    Amount fee = 0;
    static TxResult fail(std::string r) { TxResult t; t.ok = false; t.reason = std::move(r); return t; }
};

class StateReader {
public:
    virtual ~StateReader() = default;
    virtual std::optional<Coin> coin(const OutPoint& o) const = 0;
    virtual std::optional<TokenInfo> token(const Hash256& id) const = 0;
    virtual std::optional<Pool> pool(const Hash256& token) const = 0;
};

// ---- AMM math (all exact integer arithmetic)
// Max output for `in` paid into a pool with reserves (rin, rout), after the 0.3% pool fee.
Amount amm_quote(Amount in, Amount rin, Amount rout);
// Input needed to receive exactly `out` (inverse of amm_quote, rounded up). 0 if impossible.
Amount amm_quote_in(Amount out, Amount rin, Amount rout);
Amount amm_initial_shares(Amount qnt, Amount tok);      // floor(sqrt(qnt*tok)), shares incl. locked
Amount amm_add_shares(const Pool& p, Amount qnt, Amount tok);
void amm_remove_amounts(const Pool& p, Amount shares, Amount& qnt, Amount& tok);
Amount mul_div(Amount a, Amount b, Amount c);           // floor(a*b/c), 0 if c == 0 or overflow

// Context-free checks: shape, limits, dust, duplicate inputs, op fields.
TxResult check_tx_basic(const Transaction& tx, bool expect_witness);
bool valid_ticker(const std::string& s);
bool valid_token_text(const std::string& s, size_t min_len, size_t max_len);

class LedgerView : public StateReader {
public:
    explicit LedgerView(const StateReader& base) : base_(base) {}

    std::optional<Coin> coin(const OutPoint& o) const override;
    std::optional<TokenInfo> token(const Hash256& id) const override;
    std::optional<Pool> pool(const Hash256& token) const override;

    // Validate and apply a non-coinbase tx at `height`. On failure the view is unchanged.
    TxResult apply(const Transaction& tx, uint64_t height, const Hash256& genesis, bool verify_sigs);
    // Add a coinbase's outputs (amount checks are the caller's job).
    void apply_coinbase(const Transaction& tx, uint64_t height);

    // ---- contents, for committing
    const std::unordered_map<OutPoint, Coin, OutPointHasher>& created() const { return created_; }
    const std::unordered_map<OutPoint, Coin, OutPointHasher>& spent_base() const { return spent_base_; }
    const std::unordered_map<Hash256, TokenInfo, Hash256Hasher>& new_tokens() const { return tokens_; }
    const std::unordered_map<Hash256, Pool, Hash256Hasher>& pools() const { return pools_; }
    // Pools as they were in the base before this view touched them (nullopt = did not exist).
    const std::unordered_map<Hash256, std::optional<Pool>, Hash256Hasher>& pools_before() const { return pools_before_; }
    bool spends(const OutPoint& o) const { return spent_base_.count(o) || spent_created_.count(o); }

private:
    const StateReader& base_;
    std::unordered_map<OutPoint, Coin, OutPointHasher> created_;
    std::unordered_set<OutPoint, OutPointHasher> spent_created_; // created here, then spent here
    std::unordered_map<OutPoint, Coin, OutPointHasher> spent_base_;
    std::unordered_map<Hash256, TokenInfo, Hash256Hasher> tokens_;
    std::unordered_map<Hash256, Pool, Hash256Hasher> pools_;
    std::unordered_map<Hash256, std::optional<Pool>, Hash256Hasher> pools_before_;
};

// Signature check only.
bool verify_witness(const Transaction& tx, const std::vector<Coin>& coins, const Hash256& genesis, std::string* why);

} // namespace quant
