// Deterministic post-quantum wallet. Backend-agnostic: the full node feeds it blocks, the
// Termux light wallet feeds it coins fetched from peers. Stored encrypted on disk.
#pragma once
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "consensus/params.h"
#include "consensus/ledger.h"
#include "crypto/sig.h"

namespace quant {

struct WalletKey {
    uint32_t index = 0;
    KeyPair kp;
    Hash256 addr;
    std::string label;
    bool issued = false; // handed out (vs. lookahead only)
};

struct WalletCoin {
    OutPoint op;
    TxOut out;
    int64_t height = -1; // -1 = unconfirmed
    bool coinbase = false;
    bool locked = false; // spent by one of our unconfirmed txs
};

struct WalletTx {
    Hash256 txid;
    int64_t height = -1;
    int64_t time = 0;
    int64_t delta = 0;   // net effect on the QNT balance (units, signed)
    std::map<Hash256, int64_t> token_delta; // net effect on token balances
    Amount fee = 0;      // only known for our own sends
    std::string counterparty; // first foreign output address (sends)
    std::string note;
    bool coinbase = false;
    std::string kind;    // "", "token-create", "swap", "liquidity"
};

struct Balance {
    Amount confirmed = 0, unconfirmed = 0, immature = 0, locked = 0;
    Amount spendable() const { return confirmed; }
};

struct Contact { std::string name, address; };

class Wallet {
public:
    static constexpr uint32_t LOOKAHEAD = 20;

    // passphrase = optional extra seed word; password = file encryption (may be empty).
    static std::unique_ptr<Wallet> create(const std::string& path, const ChainParams& p, const std::string& mnemonic,
                                          const std::string& passphrase, const std::string& password,
                                          int64_t birth_height, std::string* err);
    static std::unique_ptr<Wallet> open(const std::string& path, const ChainParams& p, const std::string& password,
                                        std::string* err);
    static bool exists(const std::string& path);

    mutable std::recursive_mutex mu;

    bool save();
    bool change_password(const std::string& old_pw, const std::string& new_pw);
    std::string mnemonic() const { return mnemonic_; }
    const ChainParams& params() const { return p_; }

    std::string new_address(const std::string& label = "");
    std::string address_string(const Hash256& a) const { return encode_address(p_, 0, a); }
    std::vector<const WalletKey*> issued_keys() const;
    std::vector<Hash256> watched_addresses() const; // issued + lookahead
    bool is_mine(const Hash256& addr) const { return by_addr_.count(addr) != 0; }
    void set_label(const Hash256& addr, const std::string& label);

    // --- coin tracking
    void add_coin(const WalletCoin& c);
    void remove_coin(const OutPoint& o);
    void replace_coins(const std::vector<WalletCoin>& coins); // light wallet refresh
    std::vector<WalletCoin> coins() const;
    Balance balance(int64_t tip_height) const; // QNT
    std::map<Hash256, Amount> token_balances() const; // confirmed + unconfirmed, unlocked

    // Full-node backend: apply a connected/disconnected block.
    void block_connected(const Block& b, int64_t height);
    void block_disconnected(const Block& b, int64_t height);
    // Record a tx we just broadcast (locks inputs, adds change as unconfirmed).
    void tx_broadcast(const Transaction& tx, const std::string& note);
    void abandon_unconfirmed(); // unlock coins of txs that never confirmed

    std::vector<WalletTx> history() const;
    void record_tx(const WalletTx& t) { std::lock_guard l(mu); history_[t.txid] = t; }

    // --- sending. fee_per_kb 0 => minimum relay fee. Amounts are base units of the asset.
    struct Dest { std::string address; Amount amount; Hash256 asset; };
    bool create_tx(const std::vector<Dest>& dests, Amount fee_per_kb, int64_t tip_height, Transaction& out,
                   Amount* fee_out, std::string* err, bool subtract_fee = false);
    // Sweep every spendable QNT coin to one address.
    bool create_sweep(const std::string& address, Amount fee_per_kb, int64_t tip_height, Transaction& out,
                      Amount* fee_out, std::string* err);

    // --- tokens and pools. `pool` is the current pool (from the mempool view) or nullopt.
    // The whole supply of a new token goes to a fresh address of this wallet.
    bool create_token(const OpCreateToken& t, Amount fee_per_kb, int64_t tip, Transaction& out, Hash256* token_out,
                      Amount* fee_out, std::string* err);
    // Swap exactly `in`; receive at least `min_out` (the tx asks for exactly min_out; any better
    // price stays in the pool). sell=false: QNT -> token, true: token -> QNT.
    // On-chain message to `to`, paying it the gift price (or dust when there is no gift).
    bool send_message(const Hash256& to, const std::string& text, uint8_t gift, Amount fee_per_kb, int64_t tip,
                      Transaction& out, Amount* fee_out, std::string* err);
    bool swap(const Hash256& token, bool sell, Amount in, Amount min_out, Amount fee_per_kb, int64_t tip,
              Transaction& out, Amount* fee_out, std::string* err);
    // Deposit QNT + token (creates the pool if `pool` is nullopt). Shares go to this wallet.
    bool add_liquidity(const Hash256& token, Amount qnt, Amount tok, const std::optional<Pool>& pool, Amount fee_per_kb,
                       int64_t tip, Transaction& out, Amount* shares_out, Amount* fee_out, std::string* err);
    bool remove_liquidity(const Hash256& token, Amount shares, const Pool& pool, Amount fee_per_kb, int64_t tip,
                          Transaction& out, Amount* qnt_out, Amount* tok_out, Amount* fee_out, std::string* err);

    std::vector<Contact> contacts;
    int64_t birth_height = 0;
    Hash256 synced_tip;
    int64_t synced_height = -1;

private:
    Wallet(const ChainParams& p) : p_(p) {}
    // What a tx must do: pay `outs`, run `ops`, which absorb `op_in` and release `op_out`
    // (per asset). `finish` runs after coin selection (e.g. to add outputs naming a new token).
    struct Plan {
        std::vector<TxOut> outs;
        std::vector<TxOp> ops;
        std::map<Hash256, Amount> op_in, op_out;
        std::function<void(Transaction&)> finish;
        size_t extra_outs = 0; // outputs `finish` will add (for the fee estimate)
        bool subtract_fee = false, sweep = false;
        std::vector<WalletCoin> sweep_coins;
    };
    void derive_until(uint32_t count);
    bool sign_tx(Transaction& tx, const std::vector<WalletCoin>& inputs, std::string* err);
    bool build(Plan plan, int64_t tip, Amount fee_per_kb, Transaction& out, Amount* fee_out, std::string* err);
    Hash256 change_addr();
    void process_tx(const Transaction& tx, int64_t height, int64_t time);
    Bytes serialize() const;
    bool deserialize(const Bytes& b);

    const ChainParams& p_;
    std::string path_, password_, mnemonic_, passphrase_;
    Hash256 master_;
    std::vector<WalletKey> keys_;
    uint32_t next_index_ = 0;
    std::map<Hash256, size_t> by_addr_;
    std::map<OutPoint, WalletCoin> coins_;
    std::map<Hash256, WalletTx> history_;
};

} // namespace quant
