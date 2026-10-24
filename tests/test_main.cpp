// quant-tests: unit + integration tests. Run: quant-tests [filter]
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "consensus/limits.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/ledger.h"
#include "crypto/hash.h"
#include "crypto/sig.h"
#include "util/bech32.h"
#include "util/u256.h"
#include "util/log.h"

using namespace quant;

static int g_fail = 0, g_checks = 0;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

struct TestCase { const char* name; std::function<void()> fn; };
static std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
struct Reg { Reg(const char* n, std::function<void()> f) { registry().push_back({n, f}); } };
#define TEST(name) static void name(); static Reg reg_##name(#name, name); static void name()

TEST(blake3_vector) {
    // Official BLAKE3 test vector: empty input.
    Hash256 h = blake3(nullptr, 0);
    CHECK(h.hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

TEST(amount_format) {
    CHECK(format_amount(COIN) == "1.0");
    CHECK(format_amount(1) == "0.0000000001");
    CHECK(format_amount(15 * COIN / 10) == "1.5");
    CHECK(parse_amount("0.000001").value() == DUST_LIMIT);
    CHECK(parse_amount("0.0000000001").value() == 1);
    CHECK(!parse_amount("0.00000000001"));
    CHECK(!parse_amount("abc"));
    CHECK(parse_amount("3.5").value() == TAIL_SUBSIDY);
}

TEST(u256_compact) {
    U256 a = U256(1) << 230;
    CHECK(U256::from_compact(a.to_compact()) == a);
    U256 b = (U256(1) << 236) - U256(1);
    U256 bc = U256::from_compact(b.to_compact());
    CHECK(bc <= b);
    CHECK(bc.bits() == 236);
    U256 x(1000); x.mul64(7); x.div64(7);
    CHECK(x == U256(1000));
    CHECK(work_from_target((U256(1) << 255) - U256(1)) == U256(2));
    CHECK(U256::from_hash(a.to_hash()) == a);
}

TEST(subsidy_schedule) {
    CHECK(block_subsidy(0) == 0);
    CHECK(block_subsidy(1) == EMISSION_CURVE >> EMISSION_SPEED);   // ~17.5 QNT
    CHECK(block_subsidy(2) < block_subsidy(1));                    // smooth decay, no halvings
    CHECK(issued_through(3) == block_subsidy(1) + block_subsidy(2) + block_subsidy(3));
    // Checkpointed lookup matches stepping one block at a time.
    Amount iss = 0;
    for (uint64_t h = 1; h <= 10000; h++) iss += subsidy_after(iss);
    CHECK(issued_through(10000) == iss);
    // Find the tail and check it stays at 3.5 QNT forever.
    uint64_t lo = 1, hi = 20'000'000;
    while (lo < hi) { uint64_t m = (lo + hi) / 2; if (block_subsidy(m) == TAIL_SUBSIDY) hi = m; else lo = m + 1; }
    CHECK(block_subsidy(lo) == TAIL_SUBSIDY && block_subsidy(lo - 1) > TAIL_SUBSIDY);
    CHECK(block_subsidy(lo + 5'000'000) == TAIL_SUBSIDY);
    CHECK(issued_through(lo + 1000) == issued_through(lo) + 1000 * TAIL_SUBSIDY);
    double years = double(lo) * TARGET_SPACING / (365.25 * 86400);
    printf("  first reward %s QNT; tail (3.5 QNT) from block %llu (~%.1f years) with %s QNT issued; then +%s QNT/year\n",
           format_amount(block_subsidy(1)).c_str(), (unsigned long long)lo, years, format_amount(issued_through(lo - 1)).c_str(),
           format_amount(TAIL_SUBSIDY * (365 * 720)).c_str());
}

TEST(bech32m_address) {
    auto& p = params_for(Network::Test);
    Hash256 h = blake3((const uint8_t*)"x", 1);
    std::string a = encode_address(p, 0, h);
    CHECK(a.rfind("tqnt1", 0) == 0);
    uint8_t v; Hash256 back;
    CHECK(decode_address(p, a, v, back));
    CHECK(v == 0 && back == h);
    std::string bad = a; bad[10] = bad[10] == 'q' ? 'p' : 'q';
    CHECK(!decode_address(p, bad, v, back));
    CHECK(!decode_address(params_for(Network::Main), a, v, back));
}

TEST(falcon_keys) {
    Hash256 seed = blake3((const uint8_t*)"seed", 4);
    auto t0 = std::chrono::steady_clock::now();
    KeyPair kp = keypair_from_seed(seed);
    auto t1 = std::chrono::steady_clock::now();
    KeyPair kp2 = keypair_from_seed(seed);
    CHECK(kp.pk == kp2.pk && kp.sk == kp2.sk);
    CHECK(kp.pk.size() == FALCON_PK_BYTES);
    Hash256 msg = blake3((const uint8_t*)"msg", 3);
    Bytes sig = falcon_sign(kp.sk, msg);
    CHECK(falcon_verify(kp.pk, sig, msg));
    Hash256 msg2 = msg; msg2.b[0] ^= 1;
    CHECK(!falcon_verify(kp.pk, sig, msg2));
    auto ms = [](auto a, auto b) { return (long long)std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
    printf("  keygen %lld ms, falcon sig %zu bytes\n", ms(t0, t1), sig.size());
    KeyPair other = keypair_from_seed(msg);
    CHECK(other.pk != kp.pk);
}

TEST(merkle) {
    for (size_t n = 1; n <= 9; n++) {
        std::vector<Hash256> l;
        for (size_t i = 0; i < n; i++) l.push_back(blake3((const uint8_t*)&i, sizeof i));
        Hash256 root = merkle_root(l);
        for (size_t i = 0; i < n; i++) {
            auto pr = merkle_proof(l, i);
            CHECK(merkle_verify(l[i], i, n, pr, root));
            if (n > 1) CHECK(!merkle_verify(l[(i + 1) % n], i, n, pr, root));
        }
    }
}

TEST(serialize_roundtrip) {
    Transaction t;
    t.ins.push_back({{blake3((const uint8_t*)"a", 1), 3}});
    t.outs.push_back({12345678, QNT_ASSET, blake3((const uint8_t*)"b", 1)});
    t.outs.push_back({777, blake3((const uint8_t*)"tok", 3), blake3((const uint8_t*)"c", 1)});
    t.ops.push_back(OpCreateToken{"MEME", "Meme Coin", 8, 1000, "https://x"});
    t.ops.push_back(OpSwap{blake3((const uint8_t*)"tok", 3), true, 5, 4});
    t.ops.push_back(OpRemoveLiquidity{blake3((const uint8_t*)"tok", 3), 9, 8, 7});
    t.witness.push_back(WitnessRef{0});
    Bytes b = t.full_bytes();
    Reader r(b);
    Transaction t2 = Transaction::read_full(r);
    CHECK(r.empty());
    CHECK(t2.txid() == t.txid());
    CHECK(t2.full_bytes() == b);
    CHECK(t2.ops.size() == 3 && std::get<OpCreateToken>(t2.ops[0]).ticker == "MEME");
    // A plain QNT output costs one byte for its asset.
    Writer w1; write_txout(w1, TxOut{1, QNT_ASSET, Hash256{}});
    CHECK(w1.buf.size() == 1 + 1 + 32);
    // Non-canonical varint must be rejected.
    Bytes nc = {0x81, 0x00};
    Reader r2(nc);
    bool threw = false;
    try { r2.varint(); } catch (...) { threw = true; }
    CHECK(threw);
}

TEST(amm_math) {
    CHECK(amm_initial_shares(100, 100) == 100);
    CHECK(amm_initial_shares(2, 8) == 4);
    CHECK(amm_initial_shares(MAX_MONEY, MAX_TOKEN_SUPPLY) > 0);
    // 1000/1000 pool, swap 100 in: out = 100*0.997*1000 / (1000 + 99.7) = 90.66 -> 90
    CHECK(amm_quote(100, 1000, 1000) == 90);
    CHECK(amm_quote(0, 1000, 1000) == 0);
    for (Amount out : {Amount(1), Amount(50), Amount(90), Amount(500)}) {
        Amount in = amm_quote_in(out, 1000, 1000);
        CHECK(in > 0 && amm_quote(in, 1000, 1000) >= out && amm_quote(in - 1, 1000, 1000) < out);
    }
    // Huge reserves don't overflow.
    Amount big = amm_quote(MAX_MONEY / 2, MAX_MONEY, MAX_TOKEN_SUPPLY);
    CHECK(big > 0 && big < MAX_TOKEN_SUPPLY);
    Pool p{Hash256{}, 1000, 4000, 2000};
    CHECK(amm_add_shares(p, 100, 400) == 200);
    CHECK(amm_add_shares(p, 100, 100) == 50); // lopsided deposit: the smaller side counts
    Amount q, t;
    amm_remove_amounts(p, 200, q, t);
    CHECK(q == 100 && t == 400);
}

TEST(genesis) {
    for (auto n : {Network::Main, Network::Test, Network::Regtest}) {
        auto& p = params_for(n);
        CHECK(p.genesis.header.merkle_root == p.genesis.compute_merkle_root());
        CHECK(!p.genesis_hash.is_zero());
    }
    printf("  testnet genesis %s\n", params_for(Network::Test).genesis_hash.hex().c_str());
}

#include "test_chain.inc"
#include "test_tokens.inc"

int main(int argc, char** argv) {
    quant::log_set_stdout(false);
    std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0;
    for (auto& t : registry()) {
        if (!filter.empty() && std::string(t.name).find(filter) == std::string::npos) continue;
        int before = g_fail;
        printf("[ RUN  ] %s\n", t.name);
        t.fn();
        printf("[ %s ] %s\n", g_fail == before ? " OK " : "FAIL", t.name);
        ran++;
    }
    printf("\n%d tests, %d checks, %d failures\n", ran, g_checks, g_fail);
    return g_fail ? 1 : 0;
}
