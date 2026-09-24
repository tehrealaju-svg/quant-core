#include "wallet/wallet.h"

#include <algorithm>
#include <filesystem>
#include <set>

#include "consensus/limits.h"
#include "crypto/hash.h"
#include "crypto/random.h"
#include "util/log.h"
#include "wallet/mnemonic.h"

namespace quant {

// ---------------------------------------------------------------- file crypto
static constexpr uint32_t KDF_ROUNDS = 300000;

static Hash256 kdf(const std::string& pw, const uint8_t salt[16], uint32_t rounds) {
    Bytes in(salt, salt + 16);
    in.insert(in.end(), pw.begin(), pw.end());
    Hash256 k = blake3_tagged("Quant v1 wallet file kdf", in);
    uint8_t buf[48];
    std::memcpy(buf + 32, salt, 16);
    for (uint32_t i = 0; i < rounds; i++) {
        std::memcpy(buf, k.data(), 32);
        k = blake3_tagged("Quant v1 wallet file kdf round", buf, 48);
    }
    return k;
}

static void keystream_xor(const Hash256& k, const uint8_t nonce[16], Bytes& data) {
    uint8_t in[48];
    std::memcpy(in, k.data(), 32);
    std::memcpy(in + 32, nonce, 16);
    Bytes ks(data.size());
    blake3_xof("Quant v1 wallet file stream", in, 48, ks.data(), ks.size());
    for (size_t i = 0; i < data.size(); i++) data[i] ^= ks[i];
}

static Bytes seal(const Bytes& plain, const std::string& pw) {
    uint8_t salt[16], nonce[16];
    os_random(salt, 16);
    os_random(nonce, 16);
    Hash256 k = kdf(pw, salt, KDF_ROUNDS);
    Hash256 ek = blake3_keyed(k, (const uint8_t*)"enc", 3);
    Hash256 mk = blake3_keyed(k, (const uint8_t*)"mac", 3);
    Bytes ct = plain;
    keystream_xor(ek, nonce, ct);
    Writer w;
    w.raw((const uint8_t*)"QWAL", 4);
    w.u8(1);
    w.raw(salt, 16);
    w.u32le(KDF_ROUNDS);
    w.raw(nonce, 16);
    w.bytes(ct);
    Hash256 mac = blake3_keyed(mk, w.buf.data(), w.buf.size());
    w.hash(mac);
    return w.buf;
}

static bool unseal(const Bytes& file, const std::string& pw, Bytes& plain, std::string* err) {
    try {
        if (file.size() < 4 + 1 + 16 + 4 + 16 + 1 + 32) throw SerializeError("short");
        Reader r(file.data(), file.size() - 32);
        Bytes magic = r.raw(4);
        if (std::memcmp(magic.data(), "QWAL", 4) != 0 || r.u8() != 1) throw SerializeError("not a Quant wallet");
        uint8_t salt[16], nonce[16];
        r.raw(salt, 16);
        uint32_t rounds = r.u32le();
        r.raw(nonce, 16);
        Bytes ct = r.bytes(1 << 28);
        Hash256 k = kdf(pw, salt, rounds);
        Hash256 ek = blake3_keyed(k, (const uint8_t*)"enc", 3);
        Hash256 mk = blake3_keyed(k, (const uint8_t*)"mac", 3);
        Hash256 mac = blake3_keyed(mk, file.data(), file.size() - 32);
        if (std::memcmp(mac.data(), file.data() + file.size() - 32, 32) != 0) {
            if (err) *err = "wrong password (or corrupted wallet file)";
            return false;
        }
        keystream_xor(ek, nonce, ct);
        plain = std::move(ct);
        return true;
    } catch (const std::exception& e) {
        if (err) *err = e.what();
        return false;
    }
}

// ---------------------------------------------------------------- create / open / save
static Hash256 key_seed(const Hash256& master, uint32_t i) {
    uint8_t buf[16] = {'Q', 'u', 'a', 'n', 't', ' ', 'k', 'e', 'y', ' '};
    buf[12] = uint8_t(i); buf[13] = uint8_t(i >> 8); buf[14] = uint8_t(i >> 16); buf[15] = uint8_t(i >> 24);
    return blake3_keyed(master, buf, sizeof buf);
}

bool Wallet::exists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

std::unique_ptr<Wallet> Wallet::create(const std::string& path, const ChainParams& p, const std::string& mnemonic,
                                       const std::string& passphrase, const std::string& password,
                                       int64_t birth_height, std::string* err) {
    if (!mnemonic_valid(mnemonic)) { if (err) *err = "invalid seed words (check spelling / word count / checksum)"; return nullptr; }
    std::unique_ptr<Wallet> w(new Wallet(p));
    w->path_ = path;
    w->password_ = password;
    w->mnemonic_ = mnemonic_normalize(mnemonic);
    w->passphrase_ = passphrase;
    w->master_ = mnemonic_to_master(w->mnemonic_, passphrase);
    w->birth_height = birth_height;
    w->derive_until(LOOKAHEAD);
    w->new_address("default");
    if (!w->save()) { if (err) *err = "cannot write wallet file " + path; return nullptr; }
    return w;
}

std::unique_ptr<Wallet> Wallet::open(const std::string& path, const ChainParams& p, const std::string& password,
                                     std::string* err) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { if (err) *err = "cannot open " + path; return nullptr; }
    Bytes file;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) file.insert(file.end(), buf, buf + n);
    fclose(f);
    Bytes plain;
    if (!unseal(file, password, plain, err)) return nullptr;
    std::unique_ptr<Wallet> w(new Wallet(p));
    w->path_ = path;
    w->password_ = password;
    if (!w->deserialize(plain)) { if (err) *err = "wallet file is corrupted or for another network"; return nullptr; }
    return w;
}

bool Wallet::save() {
    std::lock_guard l(mu);
    Bytes data = seal(serialize(), password_);
    std::string tmp = path_ + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f) return false;
    bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
    ok = fflush(f) == 0 && ok;
    fclose(f);
    if (!ok) return false;
    std::error_code ec;
    std::filesystem::rename(tmp, path_, ec);
    return !ec;
}

bool Wallet::change_password(const std::string& old_pw, const std::string& new_pw) {
    std::lock_guard l(mu);
    if (old_pw != password_) return false;
    password_ = new_pw;
    return save();
}

Bytes Wallet::serialize() const {
    Writer w;
    w.u32le(2); // format version
    w.str(p_.name);
    w.str(mnemonic_);
    w.str(passphrase_);
    w.varint(uint64_t(birth_height));
    w.hash(synced_tip);
    w.u64le(uint64_t(synced_height));
    w.varint(next_index_);
    w.varint(keys_.size());
    for (auto& k : keys_) {
        w.varint(k.index);
        w.raw(k.kp.falcon_pk); w.raw(k.kp.falcon_sk); w.raw(k.kp.sphincs_pk); w.raw(k.kp.sphincs_sk);
        w.str(k.label);
        w.u8(k.issued);
    }
    w.varint(coins_.size());
    for (auto& [o, c] : coins_) {
        w.hash(o.txid); w.varint(o.n);
        w.varint(c.out.value); w.u8(c.out.addr_ver); w.hash(c.out.addr);
        w.u64le(uint64_t(c.height)); w.u8(c.coinbase); w.u8(c.locked);
    }
    w.varint(history_.size());
    for (auto& [h, t] : history_) {
        w.hash(t.txid); w.u64le(uint64_t(t.height)); w.u64le(uint64_t(t.time)); w.u64le(uint64_t(t.delta));
        w.varint(t.fee); w.str(t.counterparty); w.str(t.note); w.u8(t.coinbase);
    }
    w.varint(contacts.size());
    for (auto& c : contacts) { w.str(c.name); w.str(c.address); }
    return w.buf;
}

bool Wallet::deserialize(const Bytes& b) {
    try {
        Reader r(b);
        if (r.u32le() != 2) return false;
        if (r.str(32) != p_.name) return false;
        mnemonic_ = r.str(1000);
        passphrase_ = r.str(1000);
        master_ = mnemonic_to_master(mnemonic_, passphrase_);
        birth_height = int64_t(r.varint());
        synced_tip = r.hash();
        synced_height = int64_t(r.u64le());
        next_index_ = uint32_t(r.varint());
        size_t nk = r.varint();
        keys_.clear();
        by_addr_.clear();
        for (size_t i = 0; i < nk; i++) {
            WalletKey k;
            k.index = uint32_t(r.varint());
            k.kp.falcon_pk = r.raw(FALCON_PK_BYTES); k.kp.falcon_sk = r.raw(FALCON_SK_BYTES);
            k.kp.sphincs_pk = r.raw(SPHINCS_PK_BYTES); k.kp.sphincs_sk = r.raw(SPHINCS_SK_BYTES);
            k.label = r.str(200);
            k.issued = r.u8() != 0;
            k.addr = k.kp.address_hash();
            by_addr_[k.addr] = keys_.size();
            keys_.push_back(std::move(k));
        }
        size_t nc = r.varint();
        for (size_t i = 0; i < nc; i++) {
            WalletCoin c;
            c.op.txid = r.hash(); c.op.n = uint32_t(r.varint());
            c.out.value = r.varint(); c.out.addr_ver = r.u8(); c.out.addr = r.hash();
            c.height = int64_t(r.u64le()); c.coinbase = r.u8() != 0; c.locked = r.u8() != 0;
            coins_[c.op] = c;
        }
        size_t nh = r.varint();
        for (size_t i = 0; i < nh; i++) {
            WalletTx t;
            t.txid = r.hash(); t.height = int64_t(r.u64le()); t.time = int64_t(r.u64le()); t.delta = int64_t(r.u64le());
            t.fee = r.varint(); t.counterparty = r.str(200); t.note = r.str(1000); t.coinbase = r.u8() != 0;
            history_[t.txid] = t;
        }
        size_t nct = r.varint();
        for (size_t i = 0; i < nct; i++) { Contact c; c.name = r.str(200); c.address = r.str(200); contacts.push_back(c); }
        return true;
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------- keys / addresses
void Wallet::derive_until(uint32_t count) {
    while (keys_.size() < count) {
        WalletKey k;
        k.index = uint32_t(keys_.size());
        k.kp = keypair_from_seed(key_seed(master_, k.index));
        k.addr = k.kp.address_hash();
        by_addr_[k.addr] = keys_.size();
        keys_.push_back(std::move(k));
    }
}

std::string Wallet::new_address(const std::string& label) {
    std::lock_guard l(mu);
    derive_until(next_index_ + 1 + LOOKAHEAD);
    WalletKey& k = keys_[next_index_++];
    k.issued = true;
    k.label = label;
    return address_string(k.addr);
}

std::vector<const WalletKey*> Wallet::issued_keys() const {
    std::lock_guard l(mu);
    std::vector<const WalletKey*> v;
    for (auto& k : keys_) if (k.issued) v.push_back(&k);
    return v;
}

std::vector<Hash256> Wallet::watched_addresses() const {
    std::lock_guard l(mu);
    std::vector<Hash256> v;
    for (auto& k : keys_) v.push_back(k.addr);
    return v;
}

void Wallet::set_label(const Hash256& addr, const std::string& label) {
    std::lock_guard l(mu);
    auto it = by_addr_.find(addr);
    if (it != by_addr_.end()) keys_[it->second].label = label;
}

// ---------------------------------------------------------------- coins / balance / history
void Wallet::add_coin(const WalletCoin& c) {
    std::lock_guard l(mu);
    coins_[c.op] = c;
    auto it = by_addr_.find(c.out.addr);
    if (it != by_addr_.end()) {
        WalletKey& k = keys_[it->second];
        if (!k.issued) { k.issued = true; if (k.label.empty()) k.label = "restored"; }
        if (k.index >= next_index_) next_index_ = k.index + 1;
        derive_until(next_index_ + LOOKAHEAD);
    }
}

void Wallet::remove_coin(const OutPoint& o) { std::lock_guard l(mu); coins_.erase(o); }

void Wallet::replace_coins(const std::vector<WalletCoin>& coins) {
    std::lock_guard l(mu);
    coins_.clear();
    for (auto& c : coins) add_coin(c);
}

std::vector<WalletCoin> Wallet::coins() const {
    std::lock_guard l(mu);
    std::vector<WalletCoin> v;
    for (auto& [o, c] : coins_) v.push_back(c);
    return v;
}

static bool mature(const WalletCoin& c, int64_t tip) {
    return !c.coinbase || (c.height >= 0 && tip + 1 >= c.height + COINBASE_MATURITY);
}

Balance Wallet::balance(int64_t tip) const {
    std::lock_guard l(mu);
    Balance b;
    for (auto& [o, c] : coins_) {
        if (c.locked) b.locked += c.out.value;
        else if (c.height < 0) b.unconfirmed += c.out.value;
        else if (!mature(c, tip)) b.immature += c.out.value;
        else b.confirmed += c.out.value;
    }
    return b;
}

std::vector<WalletTx> Wallet::history() const {
    std::lock_guard l(mu);
    std::vector<WalletTx> v;
    for (auto& [h, t] : history_) v.push_back(t);
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) {
        int64_t ha = a.height < 0 ? INT64_MAX : a.height, hb = b.height < 0 ? INT64_MAX : b.height;
        if (ha != hb) return ha > hb;
        return a.time > b.time;
    });
    return v;
}

void Wallet::process_tx(const Transaction& tx, int64_t height, int64_t time) {
    Hash256 txid = tx.txid();
    Amount our_in = 0;
    bool all_ours = !tx.is_coinbase();
    for (auto& in : tx.ins) {
        auto it = coins_.find(in.prev);
        if (it == coins_.end()) { all_ours = false; continue; }
        our_in += it->second.out.value;
        if (height < 0) it->second.locked = true;
        else coins_.erase(it);
    }
    Amount our_out = 0;
    std::string counterparty;
    for (uint32_t n = 0; n < tx.outs.size(); n++) {
        const TxOut& o = tx.outs[n];
        if (is_mine(o.addr)) {
            our_out += o.value;
            add_coin(WalletCoin{OutPoint{txid, n}, o, height, tx.is_coinbase(), false});
        } else if (counterparty.empty()) {
            counterparty = address_string(o.addr);
        }
    }
    if (our_in == 0 && our_out == 0) return;
    WalletTx& t = history_[txid];
    bool fresh = t.txid.is_zero();
    t.txid = txid;
    t.height = height;
    if (fresh) t.time = time;
    t.delta = int64_t(our_out) - int64_t(our_in);
    t.coinbase = tx.is_coinbase();
    if (!counterparty.empty()) t.counterparty = counterparty;
    if (all_ours && our_in > 0) {
        Amount in_total = our_in, out_total = tx.total_out();
        t.fee = in_total > out_total ? in_total - out_total : 0;
    }
}

void Wallet::block_connected(const Block& b, int64_t height) {
    std::lock_guard l(mu);
    for (auto& tx : b.txs) process_tx(tx, height, int64_t(b.header.time));
    synced_tip = b.header.hash();
    synced_height = height;
}

void Wallet::block_disconnected(const Block& b, int64_t height) {
    std::lock_guard l(mu);
    for (auto& tx : b.txs) {
        auto it = history_.find(tx.txid());
        if (it == history_.end()) continue;
        if (tx.is_coinbase()) history_.erase(it); // orphaned reward is gone for good
        else it->second.height = -1;
    }
    synced_tip = b.header.prev;
    synced_height = height - 1;
}

void Wallet::tx_broadcast(const Transaction& tx, const std::string& note) {
    std::lock_guard l(mu);
    process_tx(tx, -1, now_seconds());
    auto it = history_.find(tx.txid());
    if (it != history_.end() && !note.empty()) it->second.note = note;
    save();
}

void Wallet::abandon_unconfirmed() {
    std::lock_guard l(mu);
    for (auto& [o, c] : coins_) c.locked = false;
    for (auto it = coins_.begin(); it != coins_.end();)
        it = it->second.height < 0 ? coins_.erase(it) : std::next(it);
    for (auto it = history_.begin(); it != history_.end();)
        it = it->second.height < 0 ? history_.erase(it) : std::next(it);
}

// ---------------------------------------------------------------- building + signing
static size_t estimate_size(size_t n_in, size_t n_unique, size_t n_out, bool backup) {
    size_t core = 4 + n_in * (32 + 5) + n_out * (9 + 1 + 32) + 4;
    size_t sig = backup ? (1 + SPHINCS_PK_BYTES + 32 + SPHINCS_SIG_BYTES) : (1 + FALCON_PK_BYTES + 32 + 2 + FALCON_SIG_MAX);
    return core + 3 + n_unique * sig + (n_in - n_unique) * 4;
}

bool Wallet::sign_tx(Transaction& tx, const std::vector<WalletCoin>& inputs, bool use_backup, std::string* err) {
    Hash256 sighash = signature_hash(p_.genesis_hash, tx.txid());
    tx.witness.clear();
    std::map<Hash256, uint32_t> first_use;
    for (uint32_t i = 0; i < inputs.size(); i++) {
        const Hash256& a = inputs[i].out.addr;
        auto f = first_use.find(a);
        if (f != first_use.end()) { tx.witness.push_back(WitnessRef{f->second}); continue; }
        auto k = by_addr_.find(a);
        if (k == by_addr_.end()) { if (err) *err = "missing key"; return false; }
        const KeyPair& kp = keys_[k->second].kp;
        if (use_backup)
            tx.witness.push_back(WitnessSphincs{kp.sphincs_pk, kp.falcon_pkhash(), sphincs_sign(kp.sphincs_sk, sighash)});
        else
            tx.witness.push_back(WitnessFalcon{kp.falcon_pk, kp.sphincs_pkhash(), falcon_sign(kp.falcon_sk, sighash)});
        first_use[a] = i;
    }
    return true;
}

bool Wallet::build(const std::vector<TxOut>& outs_in, std::vector<WalletCoin> pool, Amount fee_per_kb, bool use_backup,
                   bool subtract_fee, bool sweep, Transaction& out, Amount* fee_out, std::string* err) {
    if (fee_per_kb < MIN_RELAY_FEE_PER_KB) fee_per_kb = MIN_RELAY_FEE_PER_KB;
    Amount target = 0;
    for (auto& o : outs_in) target += o.value;
    std::sort(pool.begin(), pool.end(), [](auto& a, auto& b) { return a.out.value > b.out.value; });

    std::vector<WalletCoin> sel;
    Amount sel_total = 0;
    auto unique_addrs = [&] {
        std::set<Hash256> s;
        for (auto& c : sel) s.insert(c.out.addr);
        return s.size();
    };
    size_t i = 0;
    Amount fee = 0;
    for (;;) {
        size_t n_out = outs_in.size() + (sweep ? 0 : 1);
        fee = Amount(estimate_size(std::max<size_t>(sel.size(), 1), std::max<size_t>(unique_addrs(), 1), n_out, use_backup)) * fee_per_kb / 1000;
        Amount need = subtract_fee ? target : target + fee;
        if (!sel.empty() && sel_total >= need && !sweep) break;
        if (i >= pool.size()) {
            if (sweep && !sel.empty()) break;
            if (err) *err = "insufficient funds: have " + format_amount(sel_total) + ", need " + format_amount(need);
            return false;
        }
        sel.push_back(pool[i]);
        sel_total += pool[i].out.value;
        i++;
        if (sel.size() > 2000) { if (err) *err = "too many small coins; sweep first"; return false; }
    }

    Transaction tx;
    for (auto& c : sel) tx.ins.push_back(TxIn{c.op});
    tx.outs = outs_in;
    if (sweep) tx.outs[0].value = sel_total;
    if (subtract_fee || sweep) {
        if (tx.outs[0].value <= fee + DUST_LIMIT) { if (err) *err = "amount too small to cover the fee"; return false; }
        tx.outs[0].value -= fee;
    }
    Amount spent = tx.total_out();
    if (!sweep) {
        Amount change = sel_total - spent - (subtract_fee ? 0 : fee);
        if (subtract_fee) change = sel_total - spent - fee;
        if (change >= DUST_LIMIT) {
            std::string ca = new_address("(change)");
            uint8_t v; Hash256 h;
            decode_address(p_, ca, v, h);
            tx.outs.push_back(TxOut{change, ADDR_V0, h});
        }
        // else: leftover dust goes to the miner as extra fee
    }
    tx.lock_height = 0;
    if (!sign_tx(tx, sel, use_backup, err)) return false;
    Amount actual_fee = sel_total - tx.total_out();
    Amount min_fee = Amount(tx.full_size()) * MIN_RELAY_FEE_PER_KB / 1000;
    if (actual_fee < min_fee) { if (err) *err = "internal fee estimate too low"; return false; }
    out = std::move(tx);
    if (fee_out) *fee_out = actual_fee;
    return true;
}

bool Wallet::create_tx(const std::vector<Dest>& dests, Amount fee_per_kb, int64_t tip, Transaction& out,
                       Amount* fee_out, std::string* err, bool use_backup, bool subtract_fee) {
    std::lock_guard l(mu);
    if (dests.empty()) { if (err) *err = "no recipients"; return false; }
    std::vector<TxOut> outs;
    for (auto& d : dests) {
        uint8_t v; Hash256 h;
        if (!decode_address(p_, d.address, v, h) || v != ADDR_V0) { if (err) *err = "invalid address: " + d.address; return false; }
        if (d.amount < DUST_LIMIT) { if (err) *err = "minimum amount is 0.000001 QNT"; return false; }
        outs.push_back(TxOut{d.amount, v, h});
    }
    std::vector<WalletCoin> pool;
    for (auto& [o, c] : coins_) if (!c.locked && c.height >= 0 && mature(c, tip)) pool.push_back(c);
    return build(outs, pool, fee_per_kb, use_backup, subtract_fee, false, out, fee_out, err);
}

bool Wallet::create_sweep(const std::string& address, Amount fee_per_kb, int64_t tip, Transaction& out,
                          Amount* fee_out, std::string* err, bool use_backup) {
    std::lock_guard l(mu);
    uint8_t v; Hash256 h;
    if (!decode_address(p_, address, v, h)) { if (err) *err = "invalid address"; return false; }
    std::vector<WalletCoin> pool;
    for (auto& [o, c] : coins_) if (!c.locked && c.height >= 0 && mature(c, tip)) pool.push_back(c);
    if (pool.empty()) { if (err) *err = "nothing to sweep"; return false; }
    return build({TxOut{0, v, h}}, pool, fee_per_kb, use_backup, false, true, out, fee_out, err);
}

} // namespace quant
