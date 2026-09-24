// Deterministic post-quantum wallet. Backend-agnostic: the full node feeds it blocks, the
// Termux light wallet feeds it coins fetched from peers. Stored encrypted on disk.
#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include "consensus/params.h"
#include "consensus/tx_check.h"
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
    int64_t delta = 0;   // net effect on balance (units, signed)
    Amount fee = 0;      // only known for our own sends
    std::string counterparty; // first foreign output address (sends)
    std::string note;
    bool coinbase = false;
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
    std::string address_string(const Hash256& a) const { return encode_address(p_, ADDR_V0, a); }
    std::vector<const WalletKey*> issued_keys() const;
    std::vector<Hash256> watched_addresses() const; // issued + lookahead
    bool is_mine(const Hash256& addr) const { return by_addr_.count(addr) != 0; }
    void set_label(const Hash256& addr, const std::string& label);

    // --- coin tracking
    void add_coin(const WalletCoin& c);
    void remove_coin(const OutPoint& o);
    void replace_coins(const std::vector<WalletCoin>& coins); // light wallet refresh
    std::vector<WalletCoin> coins() const;
    Balance balance(int64_t tip_height) const;

    // Full-node backend: apply a connected/disconnected block.
    void block_connected(const Block& b, int64_t height);
    void block_disconnected(const Block& b, int64_t height);
    // Record a tx we just broadcast (locks inputs, adds change as unconfirmed).
    void tx_broadcast(const Transaction& tx, const std::string& note);
    void abandon_unconfirmed(); // unlock coins of txs that never confirmed

    std::vector<WalletTx> history() const;
    void record_tx(const WalletTx& t) { std::lock_guard l(mu); history_[t.txid] = t; }

    // --- sending
    struct Dest { std::string address; Amount amount; };
    // fee_per_kb 0 => minimum relay fee. use_backup => sign with SPHINCS+ (huge but lattice-proof).
    bool create_tx(const std::vector<Dest>& dests, Amount fee_per_kb, int64_t tip_height, Transaction& out,
                   Amount* fee_out, std::string* err, bool use_backup = false, bool subtract_fee = false);
    // Sweep every spendable coin to one address.
    bool create_sweep(const std::string& address, Amount fee_per_kb, int64_t tip_height, Transaction& out,
                      Amount* fee_out, std::string* err, bool use_backup = false);

    std::vector<Contact> contacts;
    int64_t birth_height = 0;
    Hash256 synced_tip;
    int64_t synced_height = -1;

private:
    Wallet(const ChainParams& p) : p_(p) {}
    void derive_until(uint32_t count);
    bool sign_tx(Transaction& tx, const std::vector<WalletCoin>& inputs, bool use_backup, std::string* err);
    bool build(const std::vector<TxOut>& outs, std::vector<WalletCoin> pool, Amount fee_per_kb, bool use_backup,
               bool subtract_fee, bool sweep, Transaction& out, Amount* fee_out, std::string* err);
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
