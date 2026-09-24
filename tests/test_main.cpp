// quant-tests: unit + integration tests. Run: quant-tests [filter]
#include <chrono>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "consensus/limits.h"
#include "consensus/params.h"
#include "consensus/pow.h"
#include "consensus/tx_check.h"
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
    CHECK(parse_amount("50").value() == INITIAL_SUBSIDY);
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
    CHECK(block_subsidy(1) == 50 * COIN);
    CHECK(block_subsidy(HALVING_INTERVAL) == 50 * COIN);
    CHECK(block_subsidy(HALVING_INTERVAL + 1) == 25 * COIN);
    // Last paying era is era 31 (reward 232 units); era 32 would be 116 < 125 -> 0.
    CHECK(block_subsidy(31 * HALVING_INTERVAL + 1) == 232);
    CHECK(block_subsidy(32 * HALVING_INTERVAL + 1) == 0);
    unsigned __int128 total = 0;
    for (uint64_t era = 0; era < 40; era++) total += (unsigned __int128)block_subsidy(era * HALVING_INTERVAL + 1) * HALVING_INTERVAL;
    CHECK(total <= MAX_MONEY);
    printf("  max supply = %s QNT, rewards end after %.0f years\n", format_amount(Amount(total)).c_str(), 32 * 8.0);
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

TEST(falcon_sphincs) {
    Hash256 seed = blake3((const uint8_t*)"seed", 4);
    auto t0 = std::chrono::steady_clock::now();
    KeyPair kp = keypair_from_seed(seed);
    auto t1 = std::chrono::steady_clock::now();
    KeyPair kp2 = keypair_from_seed(seed);
    CHECK(kp.falcon_pk == kp2.falcon_pk && kp.falcon_sk == kp2.falcon_sk);
    CHECK(kp.sphincs_pk == kp2.sphincs_pk);
    CHECK(kp.falcon_pk.size() == FALCON_PK_BYTES);
    Hash256 msg = blake3((const uint8_t*)"msg", 3);
    Bytes sig = falcon_sign(kp.falcon_sk, msg);
    CHECK(falcon_verify(kp.falcon_pk, sig, msg));
    Hash256 msg2 = msg; msg2.b[0] ^= 1;
    CHECK(!falcon_verify(kp.falcon_pk, sig, msg2));
    auto t2 = std::chrono::steady_clock::now();
    Bytes ss = sphincs_sign(kp.sphincs_sk, msg);
    auto t3 = std::chrono::steady_clock::now();
    CHECK(sphincs_verify(kp.sphincs_pk, ss, msg));
    CHECK(!sphincs_verify(kp.sphincs_pk, ss, msg2));
    auto ms = [](auto a, auto b) { return (long long)std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
    printf("  keygen %lld ms, falcon sig %zu bytes, sphincs sign %lld ms\n", ms(t0, t1), sig.size(), ms(t2, t3));
    KeyPair other = keypair_from_seed(msg);
    CHECK(other.falcon_pk != kp.falcon_pk);
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
    t.outs.push_back({12345678, 0, blake3((const uint8_t*)"b", 1)});
    t.witness.push_back(WitnessRef{0});
    Bytes b = t.full_bytes();
    Reader r(b);
    Transaction t2 = Transaction::read_full(r);
    CHECK(r.empty());
    CHECK(t2.txid() == t.txid());
    CHECK(t2.full_bytes() == b);
    // Non-canonical varint must be rejected.
    Bytes nc = {0x81, 0x00};
    Reader r2(nc);
    bool threw = false;
    try { r2.varint(); } catch (...) { threw = true; }
    CHECK(threw);
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
