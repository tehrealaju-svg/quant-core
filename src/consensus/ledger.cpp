#include "consensus/ledger.h"

#include <set>

#include "consensus/limits.h"
#include "consensus/params.h"
#include "crypto/sig.h"
#include "util/u256.h"

namespace quant {

using u128 = unsigned __int128;

static U256 u256(u128 v) { U256 r; r.w[0] = uint64_t(v); r.w[1] = uint64_t(v >> 64); return r; }
static bool fits_u64(const U256& v) { return !(v.w[1] | v.w[2] | v.w[3]); }

Amount mul_div(Amount a, Amount b, Amount c) {
    if (c == 0) return 0;
    u128 q = u128(a) * b / c;
    return q >> 64 ? 0 : Amount(q);
}

Amount amm_quote(Amount in, Amount rin, Amount rout) {
    if (in == 0 || rin == 0 || rout == 0) return 0;
    U256 in_fee = u256(u128(in) * (10'000 - POOL_FEE_BPS));
    U256 num = in_fee; num.mul64(rout);
    U256 den = u256(u128(rin) * 10'000) + in_fee;
    U256 q = num / den;
    return fits_u64(q) ? q.w[0] : 0;
}

Amount amm_quote_in(Amount out, Amount rin, Amount rout) {
    if (out == 0 || out >= rout || rin == 0) return 0;
    // in = ceil(rin * out * 10000 / ((rout - out) * 9970))
    U256 num = u256(u128(rin) * out); num.mul64(10'000);
    U256 den = u256(u128(rout - out) * (10'000 - POOL_FEE_BPS));
    U256 q = num / den;
    if (!fits_u64(q)) return 0;
    Amount in = q.w[0] + 1;
    while (in > 1 && amm_quote(in - 1, rin, rout) >= out) in--; // tighten the +1 rounding
    return amm_quote(in, rin, rout) >= out ? in : 0;
}

Amount amm_initial_shares(Amount qnt, Amount tok) {
    u128 n = u128(qnt) * tok;
    if (n == 0) return 0;
    // integer sqrt (Newton from a power of two above the root); the result fits in 64 bits
    uint64_t hi = uint64_t(n >> 64);
    int bits = hi ? 128 - __builtin_clzll(hi) : 64 - __builtin_clzll(uint64_t(n));
    u128 x = u128(1) << ((bits + 1) / 2);
    for (;;) {
        u128 y = (x + n / x) / 2;
        if (y >= x) break;
        x = y;
    }
    while (x * x > n) x--;
    return Amount(x);
}

Amount amm_add_shares(const Pool& p, Amount qnt, Amount tok) {
    if (p.qnt == 0 || p.tok == 0 || p.shares == 0) return 0;
    Amount a = mul_div(qnt, p.shares, p.qnt);
    Amount b = mul_div(tok, p.shares, p.tok);
    return a < b ? a : b;
}

void amm_remove_amounts(const Pool& p, Amount shares, Amount& qnt, Amount& tok) {
    qnt = mul_div(shares, p.qnt, p.shares);
    tok = mul_div(shares, p.tok, p.shares);
}

bool valid_ticker(const std::string& s) {
    if (s.empty() || s.size() > MAX_TICKER) return false;
    for (char c : s) if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
    return true;
}

bool valid_token_text(const std::string& s, size_t min_len, size_t max_len) {
    if (s.size() < min_len || s.size() > max_len) return false;
    for (unsigned char c : s) if (c < 0x20 || c > 0x7e) return false;
    return true;
}

TxResult check_tx_basic(const Transaction& tx, bool expect_witness) {
    if (tx.version != 2) return TxResult::fail("bad-version");
    if (tx.ops.size() > MAX_TX_OPS) return TxResult::fail("too-many-ops");
    if (tx.is_coinbase()) {
        if (!tx.witness.empty()) return TxResult::fail("coinbase-witness");
        if (!tx.ops.empty()) return TxResult::fail("coinbase-ops");
    } else {
        if (tx.outs.empty()) return TxResult::fail("no-outputs");
        if (!tx.extra.empty()) return TxResult::fail("extra-in-non-coinbase");
        if (expect_witness && tx.witness.size() != tx.ins.size()) return TxResult::fail("witness-count");
        std::set<OutPoint> seen;
        for (auto& in : tx.ins)
            if (!seen.insert(in.prev).second) return TxResult::fail("duplicate-input");
    }
    Amount qnt = 0;
    for (auto& o : tx.outs) {
        if (o.value == 0) return TxResult::fail("zero-output");
        if (o.is_qnt()) {
            if (!tx.is_coinbase() && o.value < DUST_LIMIT) return TxResult::fail("dust-output");
            if (o.value > MAX_MONEY) return TxResult::fail("output-too-large");
            qnt += o.value;
            if (qnt > MAX_MONEY) return TxResult::fail("outputs-overflow");
        } else {
            if (tx.is_coinbase()) return TxResult::fail("coinbase-token-output");
            if (o.value > MAX_TOKEN_SUPPLY) return TxResult::fail("output-too-large");
        }
    }
    int messages = 0;
    for (auto& op : tx.ops) {
        if (auto* c = std::get_if<OpCreateToken>(&op)) {
            if (!valid_ticker(c->ticker)) return TxResult::fail("bad-ticker");
            if (!valid_token_text(c->name, 1, MAX_TOKEN_NAME)) return TxResult::fail("bad-token-name");
            if (!valid_token_text(c->uri, 0, MAX_TOKEN_URI)) return TxResult::fail("bad-token-uri");
            if (c->decimals > MAX_TOKEN_DECIMALS) return TxResult::fail("bad-decimals");
            if (c->supply == 0 || c->supply > MAX_TOKEN_SUPPLY) return TxResult::fail("bad-supply");
        } else if (auto* p = std::get_if<OpPoolCreate>(&op)) {
            if (p->token.is_zero() || !p->qnt || !p->tok || !p->shares) return TxResult::fail("bad-pool-create");
        } else if (auto* a = std::get_if<OpAddLiquidity>(&op)) {
            if (a->token.is_zero() || !a->qnt || !a->tok || !a->shares) return TxResult::fail("bad-add-liquidity");
        } else if (auto* r = std::get_if<OpRemoveLiquidity>(&op)) {
            if (r->token.is_zero() || !r->shares || (!r->qnt && !r->tok)) return TxResult::fail("bad-remove-liquidity");
        } else if (auto* s = std::get_if<OpSwap>(&op)) {
            if (s->token.is_zero() || !s->in || !s->out) return TxResult::fail("bad-swap");
        } else if (auto* m = std::get_if<OpMessage>(&op)) {
            if (++messages > 1) return TxResult::fail("too-many-messages");
            if (m->gift >= GIFT_COUNT) return TxResult::fail("bad-gift");
            if (m->text.size() > MAX_MESSAGE_TEXT) return TxResult::fail("message-too-long");
            for (unsigned char ch : m->text) if (ch < 0x20 || ch == 0x7f) return TxResult::fail("bad-message-text");
            if (m->text.empty() && !m->gift) return TxResult::fail("empty-message");
            Amount need = std::max(DUST_LIMIT, GIFT_PRICE[m->gift]), paid = 0;
            for (auto& o : tx.outs) if (o.is_qnt() && o.addr == m->to) paid += o.value;
            if (paid < need) return TxResult::fail("message-underpaid");
        }
    }
    return {};
}

bool verify_witness(const Transaction& tx, const std::vector<Coin>& coins, const Hash256& genesis, std::string* why) {
    auto fail = [&](const char* r) { if (why) *why = r; return false; };
    if (tx.witness.size() != tx.ins.size()) return fail("witness-count");
    Hash256 sighash = signature_hash(genesis, tx.txid());
    for (size_t i = 0; i < tx.ins.size(); i++) {
        const Hash256& addr = coins[i].out.addr;
        const Witness& w = tx.witness[i];
        if (auto* r = std::get_if<WitnessRef>(&w)) {
            // Reuse the signature of an earlier input that pays to the same address.
            if (r->input >= i) return fail("ref-forward");
            if (std::holds_alternative<WitnessRef>(tx.witness[r->input])) return fail("ref-chain");
            if (coins[r->input].out.addr != addr) return fail("ref-address-mismatch");
        } else if (auto* f = std::get_if<WitnessFalcon>(&w)) {
            if (address_hash(f->pk) != addr) return fail("key-mismatch");
            if (!falcon_verify(f->pk, f->sig, sighash)) return fail("bad-signature");
        }
    }
    return true;
}

// ---------------------------------------------------------------- LedgerView
std::optional<Coin> LedgerView::coin(const OutPoint& o) const {
    if (spent_base_.count(o)) return std::nullopt;
    if (auto it = created_.find(o); it != created_.end()) return it->second;
    if (spent_created_.count(o)) return std::nullopt;
    return base_.coin(o);
}

std::optional<TokenInfo> LedgerView::token(const Hash256& id) const {
    if (auto it = tokens_.find(id); it != tokens_.end()) return it->second;
    return base_.token(id);
}

std::optional<Pool> LedgerView::pool(const Hash256& t) const {
    if (auto it = pools_.find(t); it != pools_.end()) return it->second;
    return base_.pool(t);
}

void LedgerView::apply_coinbase(const Transaction& tx, uint64_t height) {
    Hash256 id = tx.txid();
    for (uint32_t n = 0; n < tx.outs.size(); n++) created_[OutPoint{id, n}] = Coin{tx.outs[n], height, true};
}

TxResult LedgerView::apply(const Transaction& tx, uint64_t height, const Hash256& genesis, bool verify_sigs) {
    if (tx.is_coinbase()) return TxResult::fail("coinbase-in-apply");
    if (tx.lock_height > height) return TxResult::fail("locked");

    // Per-asset flows. plus = inputs + what ops release; minus = outputs + what ops absorb.
    std::map<Hash256, u128> plus, minus;
    std::vector<Coin> coins;
    coins.reserve(tx.ins.size());
    for (auto& in : tx.ins) {
        auto c = coin(in.prev);
        if (!c) return TxResult::fail("missing-or-spent-input");
        if (c->coinbase && height < c->height + uint64_t(maturity_for_genesis(genesis))) return TxResult::fail("immature-coinbase");
        plus[c->out.asset] += c->out.value;
        coins.push_back(*c);
    }
    for (auto& o : tx.outs) minus[o.asset] += o.value;

    // Ops run in order against a scratch copy of the pools they touch.
    std::unordered_map<Hash256, std::optional<Pool>, Hash256Hasher> touched;
    std::unordered_map<Hash256, TokenInfo, Hash256Hasher> minted;
    Hash256 txid = tx.txid();
    auto get_pool = [&](const Hash256& t) -> std::optional<Pool>& {
        auto it = touched.find(t);
        if (it == touched.end()) it = touched.emplace(t, pool(t)).first;
        return it->second;
    };
    auto token_known = [&](const Hash256& t) { return minted.count(t) || token(t).has_value(); };

    for (uint32_t i = 0; i < tx.ops.size(); i++) {
        const TxOp& op = tx.ops[i];
        if (auto* c = std::get_if<OpCreateToken>(&op)) {
            Hash256 id = token_id(tx.ins[0].prev, i);
            if (token_known(id)) return TxResult::fail("token-exists");
            minted[id] = TokenInfo{id, c->ticker, c->name, c->uri, c->decimals, c->supply, txid, height};
            plus[id] += c->supply;
        } else if (auto* p = std::get_if<OpPoolCreate>(&op)) {
            if (!token_known(p->token)) return TxResult::fail("unknown-token");
            auto& pl = get_pool(p->token);
            if (pl) return TxResult::fail("pool-exists");
            if (p->qnt > MAX_MONEY) return TxResult::fail("pool-too-large");
            Amount total = amm_initial_shares(p->qnt, p->tok);
            if (total <= MIN_LIQUIDITY || p->shares > total - MIN_LIQUIDITY) return TxResult::fail("pool-shares-too-high");
            pl = Pool{p->token, p->qnt, p->tok, p->shares + MIN_LIQUIDITY};
            minus[QNT_ASSET] += p->qnt; minus[p->token] += p->tok;
            plus[pool_share_id(p->token)] += p->shares;
        } else if (auto* a = std::get_if<OpAddLiquidity>(&op)) {
            auto& pl = get_pool(a->token);
            if (!pl) return TxResult::fail("no-pool");
            if (a->shares > amm_add_shares(*pl, a->qnt, a->tok)) return TxResult::fail("liquidity-shares-too-high");
            if (u128(pl->qnt) + a->qnt > MAX_MONEY || u128(pl->tok) + a->tok > MAX_TOKEN_SUPPLY ||
                u128(pl->shares) + a->shares > MAX_TOKEN_SUPPLY) return TxResult::fail("pool-too-large");
            pl->qnt += a->qnt; pl->tok += a->tok; pl->shares += a->shares;
            minus[QNT_ASSET] += a->qnt; minus[a->token] += a->tok;
            plus[pool_share_id(a->token)] += a->shares;
        } else if (auto* r = std::get_if<OpRemoveLiquidity>(&op)) {
            auto& pl = get_pool(r->token);
            if (!pl) return TxResult::fail("no-pool");
            if (r->shares > pl->shares - MIN_LIQUIDITY) return TxResult::fail("remove-too-many-shares");
            Amount mq, mt;
            amm_remove_amounts(*pl, r->shares, mq, mt);
            if (r->qnt > mq || r->tok > mt) return TxResult::fail("remove-amounts-too-high");
            pl->qnt -= r->qnt; pl->tok -= r->tok; pl->shares -= r->shares;
            minus[pool_share_id(r->token)] += r->shares;
            plus[QNT_ASSET] += r->qnt; plus[r->token] += r->tok;
        } else if (auto* s = std::get_if<OpSwap>(&op)) {
            auto& pl = get_pool(s->token);
            if (!pl) return TxResult::fail("no-pool");
            Amount& rin = s->sell ? pl->tok : pl->qnt;
            Amount& rout = s->sell ? pl->qnt : pl->tok;
            if (s->out >= rout || s->out > amm_quote(s->in, rin, rout)) return TxResult::fail("swap-price-moved");
            if (u128(rin) + s->in > (s->sell ? MAX_TOKEN_SUPPLY : MAX_MONEY)) return TxResult::fail("pool-too-large");
            rin += s->in; rout -= s->out;
            Hash256 in_asset = s->sell ? s->token : QNT_ASSET, out_asset = s->sell ? QNT_ASSET : s->token;
            minus[in_asset] += s->in;
            plus[out_asset] += s->out;
        } else if (auto* m = std::get_if<OpMessage>(&op)) {
            bool from_input = false;
            for (auto& c : coins) from_input |= c.out.addr == m->from;
            if (!from_input) return TxResult::fail("message-from-not-input");
        }
    }

    // Every asset balances exactly; QNT may leave a fee for the miner.
    std::set<Hash256> assets;
    for (auto& [a, v] : plus) assets.insert(a);
    for (auto& [a, v] : minus) assets.insert(a);
    Amount fee = 0;
    for (auto& a : assets) {
        u128 p = plus[a], m = minus[a];
        if (a.is_zero()) {
            if (m > p) return TxResult::fail("outputs-exceed-inputs");
            if (p - m > MAX_MONEY) return TxResult::fail("fee-too-large");
            fee = Amount(p - m);
        } else if (p != m) {
            return TxResult::fail(p > m ? "token-not-balanced (unspent)" : "token-not-balanced (overspent)");
        }
    }

    if (verify_sigs) {
        std::string why;
        if (!verify_witness(tx, coins, genesis, &why)) return TxResult::fail(why);
    }

    // Commit into the view.
    for (auto& in : tx.ins) {
        if (created_.erase(in.prev)) spent_created_.insert(in.prev);
        else spent_base_[in.prev] = base_.coin(in.prev).value();
    }
    for (uint32_t n = 0; n < tx.outs.size(); n++) created_[OutPoint{txid, n}] = Coin{tx.outs[n], height, false};
    for (auto& [id, t] : minted) tokens_[id] = t;
    for (auto& [t, pl] : touched) {
        if (!pools_before_.count(t) && !pools_.count(t)) pools_before_[t] = base_.pool(t);
        pools_[t] = *pl;
    }
    TxResult r;
    r.fee = fee;
    return r;
}

} // namespace quant
