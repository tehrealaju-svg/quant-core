#include "wallet/wallet.h"

#include <algorithm>
#include <filesystem>
#include <mutex>
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
    // The salt + stretched key are reused while the password stays the same (fresh nonce every
    // time), so frequent saves don't redo 300k hash rounds.
    static std::mutex cache_mu;
    static std::string cache_pw;
    static uint8_t cache_salt[16];
    static Hash256 cache_key;
    static bool cached = false;
    uint8_t salt[16], nonce[16];
    os_random(nonce, 16);
    Hash256 k;
    {
        std::lock_guard l(cache_mu);
        if (!cached || cache_pw != pw) {
            os_random(cache_salt, 16);
            cache_key = kdf(pw, cache_salt, KDF_ROUNDS);
            cache_pw = pw;
            cached = true;
        }
        std::memcpy(salt, cache_salt, 16);
        k = cache_key;
    }
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
    w.u32le(3); // format version
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
        w.raw(k.kp.pk); w.raw(k.kp.sk);
        w.str(k.label);
        w.u8(k.issued);
    }
    w.varint(coins_.size());
    for (auto& [o, c] : coins_) {
        w.hash(o.txid); w.varint(o.n);
        write_txout(w, c.out);
        w.u64le(uint64_t(c.height)); w.u8(c.coinbase); w.u8(c.locked);
    }
    w.varint(history_.size());
    for (auto& [h, t] : history_) {
        w.hash(t.txid); w.u64le(uint64_t(t.height)); w.u64le(uint64_t(t.time)); w.u64le(uint64_t(t.delta));
        w.varint(t.fee); w.str(t.counterparty); w.str(t.note); w.u8(t.coinbase);
        w.str(t.kind);
        w.varint(t.token_delta.size());
        for (auto& [a, d] : t.token_delta) { w.hash(a); w.u64le(uint64_t(d)); }
    }
    w.varint(contacts.size());
    for (auto& c : contacts) { w.str(c.name); w.str(c.address); }
    return w.buf;
}

bool Wallet::deserialize(const Bytes& b) {
    try {
        Reader r(b);
        if (r.u32le() != 3) return false;
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
            k.kp.pk = r.raw(FALCON_PK_BYTES); k.kp.sk = r.raw(FALCON_SK_BYTES);
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
            c.out = read_txout(r);
            c.height = int64_t(r.u64le()); c.coinbase = r.u8() != 0; c.locked = r.u8() != 0;
            coins_[c.op] = c;
        }
        size_t nh = r.varint();
        for (size_t i = 0; i < nh; i++) {
            WalletTx t;
            t.txid = r.hash(); t.height = int64_t(r.u64le()); t.time = int64_t(r.u64le()); t.delta = int64_t(r.u64le());
            t.fee = r.varint(); t.counterparty = r.str(200); t.note = r.str(1000); t.coinbase = r.u8() != 0;
            t.kind = r.str(32);
            size_t nd = r.varint_max(1000);
            for (size_t j = 0; j < nd; j++) { Hash256 a = r.hash(); t.token_delta[a] = int64_t(r.u64le()); }
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

static bool mature(const WalletCoin& c, int64_t tip, int maturity) {
    return !c.coinbase || (c.height >= 0 && tip + 1 >= c.height + maturity);
}

Balance Wallet::balance(int64_t tip) const {
    std::lock_guard l(mu);
    Balance b;
    for (auto& [o, c] : coins_) {
        if (!c.out.is_qnt()) continue;
        if (c.locked) b.locked += c.out.value;
        else if (c.height < 0) b.unconfirmed += c.out.value;
        else if (!mature(c, tip, p_.coinbase_maturity)) b.immature += c.out.value;
        else b.confirmed += c.out.value;
    }
    return b;
}

std::map<Hash256, Amount> Wallet::token_balances() const {
    std::lock_guard l(mu);
    std::map<Hash256, Amount> m;
    for (auto& [o, c] : coins_) if (!c.out.is_qnt() && !c.locked) m[c.out.asset] += c.out.value;
    return m;
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
    std::map<Hash256, int64_t> delta; // per asset, zero id = QNT
    Amount qnt_in = 0;
    bool any = false, all_ours = !tx.is_coinbase();
    for (auto& in : tx.ins) {
        auto it = coins_.find(in.prev);
        if (it == coins_.end()) { all_ours = false; continue; }
        any = true;
        delta[it->second.out.asset] -= int64_t(it->second.out.value);
        if (it->second.out.is_qnt()) qnt_in += it->second.out.value;
        if (height < 0) it->second.locked = true;
        else coins_.erase(it);
    }
    std::string counterparty;
    for (uint32_t n = 0; n < tx.outs.size(); n++) {
        const TxOut& o = tx.outs[n];
        if (is_mine(o.addr)) {
            any = true;
            delta[o.asset] += int64_t(o.value);
            add_coin(WalletCoin{OutPoint{txid, n}, o, height, tx.is_coinbase(), false});
        } else if (counterparty.empty()) {
            counterparty = address_string(o.addr);
        }
    }
    if (!any) return;
    WalletTx& t = history_[txid];
    bool fresh = t.txid.is_zero();
    t.txid = txid;
    t.height = height;
    if (fresh) t.time = time;
    t.delta = delta[QNT_ASSET];
    t.token_delta.clear();
    for (auto& [a, d] : delta) if (!a.is_zero() && d) t.token_delta[a] = d;
    t.coinbase = tx.is_coinbase();
    if (!counterparty.empty()) t.counterparty = counterparty;
    // Fee = QNT that went in (inputs + released by ops) minus QNT that came out (outputs + absorbed).
    int64_t op_q = 0;
    for (auto& op : tx.ops) {
        if (auto* m = std::get_if<OpMessage>(&op)) { if (t.kind.empty() || t.kind == "send" || t.kind == "receive") t.kind = m->gift ? "gift" : "message"; }
        else if (std::holds_alternative<OpCreateToken>(op)) t.kind = "token-create";
        else if (auto* s = std::get_if<OpSwap>(&op)) { t.kind = "swap"; op_q += s->sell ? int64_t(s->out) : -int64_t(s->in); }
        else if (auto* p = std::get_if<OpPoolCreate>(&op)) { t.kind = "liquidity"; op_q -= int64_t(p->qnt); }
        else if (auto* a = std::get_if<OpAddLiquidity>(&op)) { t.kind = "liquidity"; op_q -= int64_t(a->qnt); }
        else if (auto* r = std::get_if<OpRemoveLiquidity>(&op)) { t.kind = "liquidity"; op_q += int64_t(r->qnt); }
    }
    if (all_ours && qnt_in > 0) {
        int64_t f = int64_t(qnt_in) + op_q - int64_t(tx.total_qnt_out());
        t.fee = f > 0 ? Amount(f) : 0;
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
static size_t estimate_size(size_t n_in, size_t n_unique, size_t n_out, size_t n_ops) {
    size_t core = 8 + n_in * (32 + 5) + n_out * (9 + 33 + 32) + n_ops * 160 + 4;
    size_t sig = 1 + FALCON_PK_BYTES + 2 + FALCON_SIG_MAX;
    return core + 3 + n_unique * sig + (n_in - n_unique) * 4;
}

bool Wallet::sign_tx(Transaction& tx, const std::vector<WalletCoin>& inputs, std::string* err) {
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
        tx.witness.push_back(WitnessFalcon{kp.pk, falcon_sign(kp.sk, sighash)});
        first_use[a] = i;
    }
    return true;
}

Hash256 Wallet::change_addr() {
    std::string ca = new_address("(change)");
    uint8_t v; Hash256 h;
    decode_address(p_, ca, v, h);
    return h;
}

bool Wallet::build(Plan plan, int64_t tip, Amount fee_per_kb, Transaction& out, Amount* fee_out, std::string* err) {
    if (fee_per_kb < MIN_RELAY_FEE_PER_KB) fee_per_kb = MIN_RELAY_FEE_PER_KB;
    auto spendable = [&](const WalletCoin& c) { return !c.locked && c.height >= 0 && mature(c, tip, p_.coinbase_maturity); };

    // Net amount each asset needs from our coins: outputs + absorbed by ops - released by ops.
    std::map<Hash256, __int128> need;
    for (auto& o : plan.outs) need[o.asset] += o.value;
    for (auto& [a, v] : plan.op_in) need[a] += v;
    for (auto& [a, v] : plan.op_out) need[a] -= v;

    std::vector<WalletCoin> sel;
    std::vector<TxOut> change;
    // Tokens first (no fee in tokens).
    for (auto& [asset, n] : need) {
        if (asset.is_zero()) continue;
        Amount have = 0;
        if (n > 0) {
            std::vector<WalletCoin> pool;
            for (auto& [o, c] : coins_) if (c.out.asset == asset && spendable(c)) pool.push_back(c);
            std::sort(pool.begin(), pool.end(), [](auto& a, auto& b) { return a.out.value > b.out.value; });
            for (auto& c : pool) {
                if (__int128(have) >= n) break;
                sel.push_back(c);
                have += c.out.value;
            }
            if (__int128(have) < n) { if (err) *err = "insufficient token balance"; return false; }
        }
        __int128 left = __int128(have) - n;
        if (left > 0) change.push_back(TxOut{Amount(left), asset, Hash256{}});
    }

    // QNT: inputs to cover the net need plus the fee (always at least one input).
    std::vector<WalletCoin> qpool = plan.sweep ? plan.sweep_coins : std::vector<WalletCoin>{};
    if (!plan.sweep)
        for (auto& [o, c] : coins_) if (c.out.is_qnt() && spendable(c)) qpool.push_back(c);
    std::sort(qpool.begin(), qpool.end(), [](auto& a, auto& b) { return a.out.value > b.out.value; });
    __int128 qneed = need.count(QNT_ASSET) ? need[QNT_ASSET] : 0;
    Amount qhave = 0, fee = 0;
    size_t qi = 0, qcount = 0;
    auto unique_addrs = [&] {
        std::set<Hash256> s;
        for (auto& c : sel) s.insert(c.out.addr);
        return std::max<size_t>(s.size(), 1);
    };
    for (;;) {
        size_t n_out = plan.outs.size() + change.size() + plan.extra_outs + (plan.sweep ? 0 : 1);
        fee = Amount(estimate_size(std::max<size_t>(sel.size(), 1), unique_addrs(), n_out, plan.ops.size())) * fee_per_kb / 1000;
        __int128 want = plan.subtract_fee ? qneed : qneed + fee;
        if (qcount > 0 && __int128(qhave) >= want && !plan.sweep) break;
        if (qi >= qpool.size()) {
            if (plan.sweep && qcount) break;
            if (err) *err = "insufficient QNT: have " + format_amount(qhave) + ", need " + format_amount(Amount(want > 0 ? want : 0));
            return false;
        }
        sel.push_back(qpool[qi]);
        qhave += qpool[qi].out.value;
        qi++; qcount++;
        if (sel.size() > 2000) { if (err) *err = "too many small coins; sweep first"; return false; }
    }

    Transaction tx;
    for (auto& c : sel) tx.ins.push_back(TxIn{c.op});
    tx.outs = plan.outs;
    tx.ops = plan.ops;
    if (plan.sweep) tx.outs[0].value = qhave;
    if (plan.subtract_fee || plan.sweep) {
        if (tx.outs[0].value <= fee + DUST_LIMIT) { if (err) *err = "amount too small to cover the fee"; return false; }
        tx.outs[0].value -= fee;
    }
    if (!plan.sweep) {
        __int128 qchange = __int128(qhave) - qneed - (plan.subtract_fee ? 0 : fee);
        if (qchange >= DUST_LIMIT) change.push_back(TxOut{Amount(qchange), QNT_ASSET, Hash256{}});
        // else: leftover dust goes to the miner as extra fee
    }
    if (!change.empty()) {
        Hash256 ca = change_addr();
        for (auto& c : change) { c.addr = ca; tx.outs.push_back(c); }
    }
    if (plan.finish) plan.finish(tx);
    tx.lock_height = 0;
    if (!sign_tx(tx, sel, err)) return false;
    __int128 actual = __int128(qhave) + (plan.op_out.count(QNT_ASSET) ? plan.op_out[QNT_ASSET] : 0) -
                      tx.total_qnt_out() - (plan.op_in.count(QNT_ASSET) ? plan.op_in[QNT_ASSET] : 0);
    Amount min_fee = Amount(tx.full_size()) * MIN_RELAY_FEE_PER_KB / 1000;
    if (actual < __int128(min_fee)) { if (err) *err = "internal fee estimate too low"; return false; }
    out = std::move(tx);
    if (fee_out) *fee_out = Amount(actual);
    return true;
}

bool Wallet::create_tx(const std::vector<Dest>& dests, Amount fee_per_kb, int64_t tip, Transaction& out,
                       Amount* fee_out, std::string* err, bool subtract_fee) {
    std::lock_guard l(mu);
    if (dests.empty()) { if (err) *err = "no recipients"; return false; }
    Plan plan;
    for (auto& d : dests) {
        uint8_t v; Hash256 h;
        if (!decode_address(p_, d.address, v, h) || v != 0) { if (err) *err = "invalid address: " + d.address; return false; }
        if (d.asset.is_zero() && d.amount < DUST_LIMIT) { if (err) *err = "minimum amount is 0.000001 QNT"; return false; }
        if (d.amount == 0) { if (err) *err = "amount must be positive"; return false; }
        plan.outs.push_back(TxOut{d.amount, d.asset, h});
    }
    if (subtract_fee && !plan.outs[0].is_qnt()) { if (err) *err = "can only subtract the fee from a QNT payment"; return false; }
    plan.subtract_fee = subtract_fee;
    return build(std::move(plan), tip, fee_per_kb, out, fee_out, err);
}

bool Wallet::create_sweep(const std::string& address, Amount fee_per_kb, int64_t tip, Transaction& out,
                          Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    uint8_t v; Hash256 h;
    if (!decode_address(p_, address, v, h)) { if (err) *err = "invalid address"; return false; }
    Plan plan;
    for (auto& [o, c] : coins_) if (c.out.is_qnt() && !c.locked && c.height >= 0 && mature(c, tip, p_.coinbase_maturity)) plan.sweep_coins.push_back(c);
    if (plan.sweep_coins.empty()) { if (err) *err = "nothing to sweep"; return false; }
    plan.sweep = true;
    plan.outs.push_back(TxOut{0, QNT_ASSET, h});
    return build(std::move(plan), tip, fee_per_kb, out, fee_out, err);
}

bool Wallet::create_token(const OpCreateToken& t, Amount fee_per_kb, int64_t tip, Transaction& out, Hash256* token_out,
                          Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    Plan plan;
    plan.ops.push_back(t);
    plan.extra_outs = 1;
    Hash256 owner = change_addr();
    Hash256 id;
    plan.finish = [&](Transaction& tx) {
        id = token_id(tx.ins[0].prev, 0);
        tx.outs.push_back(TxOut{t.supply, id, owner});
    };
    TxResult basic;
    if (!valid_ticker(t.ticker)) { if (err) *err = "ticker must be 1-10 characters A-Z / 0-9"; return false; }
    if (!valid_token_text(t.name, 1, MAX_TOKEN_NAME)) { if (err) *err = "name must be 1-32 printable characters"; return false; }
    if (!valid_token_text(t.uri, 0, MAX_TOKEN_URI)) { if (err) *err = "uri must be at most 120 printable characters"; return false; }
    if (t.decimals > MAX_TOKEN_DECIMALS) { if (err) *err = "decimals must be 0-10"; return false; }
    if (t.supply == 0 || t.supply > MAX_TOKEN_SUPPLY) { if (err) *err = "supply out of range"; return false; }
    if (!build(std::move(plan), tip, fee_per_kb, out, fee_out, err)) return false;
    if (token_out) *token_out = id;
    return true;
}

bool Wallet::send_message(const Hash256& to, const std::string& text, uint8_t gift, Amount fee_per_kb, int64_t tip,
                          Transaction& out, Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    if (gift >= GIFT_COUNT) { if (err) *err = "unknown gift"; return false; }
    if (text.size() > MAX_MESSAGE_TEXT) { if (err) *err = "message is longer than 280 bytes"; return false; }
    if (text.empty() && !gift) { if (err) *err = "empty message"; return false; }
    for (unsigned char c : text) if (c < 0x20 || c == 0x7f) { if (err) *err = "message has control characters"; return false; }
    Plan plan;
    plan.outs.push_back(TxOut{std::max(DUST_LIMIT, GIFT_PRICE[gift]), QNT_ASSET, to});
    plan.ops.push_back(OpMessage{Hash256{}, to, gift, text});
    plan.extra_outs = (text.size() + 73) / 74 + 1; // the text is longer than the 160 bytes estimated per op
    plan.finish = [this](Transaction& tx) {
        auto it = coins_.find(tx.ins[0].prev);
        if (it != coins_.end()) std::get<OpMessage>(tx.ops[0]).from = it->second.out.addr;
    };
    return build(std::move(plan), tip, fee_per_kb, out, fee_out, err);
}

bool Wallet::swap(const Hash256& token, bool sell, Amount in, Amount min_out, Amount fee_per_kb, int64_t tip,
                  Transaction& out, Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    if (in == 0 || min_out == 0) { if (err) *err = "amounts must be positive"; return false; }
    if (!sell && min_out == 0) return false;
    if (sell && min_out < DUST_LIMIT) { if (err) *err = "you would receive less than 0.000001 QNT"; return false; }
    Plan plan;
    plan.ops.push_back(OpSwap{token, sell, in, min_out});
    plan.op_in[sell ? token : QNT_ASSET] = in;
    plan.op_out[sell ? QNT_ASSET : token] = min_out;
    return build(std::move(plan), tip, fee_per_kb, out, fee_out, err);
}

bool Wallet::add_liquidity(const Hash256& token, Amount qnt, Amount tok, const std::optional<Pool>& pool, Amount fee_per_kb,
                           int64_t tip, Transaction& out, Amount* shares_out, Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    if (!qnt || !tok) { if (err) *err = "amounts must be positive"; return false; }
    Plan plan;
    Amount shares;
    if (!pool) {
        Amount total = amm_initial_shares(qnt, tok);
        if (total <= MIN_LIQUIDITY) { if (err) *err = "first deposit too small"; return false; }
        shares = total - MIN_LIQUIDITY;
        plan.ops.push_back(OpPoolCreate{token, qnt, tok, shares});
    } else {
        shares = amm_add_shares(*pool, qnt, tok);
        if (!shares) { if (err) *err = "deposit too small"; return false; }
        plan.ops.push_back(OpAddLiquidity{token, qnt, tok, shares});
    }
    plan.op_in[QNT_ASSET] = qnt;
    plan.op_in[token] = tok;
    plan.op_out[pool_share_id(token)] = shares;
    if (!build(std::move(plan), tip, fee_per_kb, out, fee_out, err)) return false;
    if (shares_out) *shares_out = shares;
    return true;
}

bool Wallet::remove_liquidity(const Hash256& token, Amount shares, const Pool& pool, Amount fee_per_kb, int64_t tip,
                              Transaction& out, Amount* qnt_out, Amount* tok_out, Amount* fee_out, std::string* err) {
    std::lock_guard l(mu);
    if (!shares || shares > pool.shares - MIN_LIQUIDITY) { if (err) *err = "bad share amount"; return false; }
    Amount q, t;
    amm_remove_amounts(pool, shares, q, t);
    if (!q && !t) { if (err) *err = "too few shares"; return false; }
    Plan plan;
    plan.ops.push_back(OpRemoveLiquidity{token, shares, q, t});
    plan.op_in[pool_share_id(token)] = shares;
    if (q) plan.op_out[QNT_ASSET] = q;
    if (t) plan.op_out[token] = t;
    if (!build(std::move(plan), tip, fee_per_kb, out, fee_out, err)) return false;
    if (qnt_out) *qnt_out = q;
    if (tok_out) *tok_out = t;
    return true;
}

} // namespace quant
