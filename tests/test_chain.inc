// Chain / wallet integration tests on a private regtest chain.
#include <filesystem>

#include "chain/mempool.h"
#include "crypto/random.h"
#include "miner/miner.h"
#include "node/node.h"
#include "wallet/mnemonic.h"

static std::string temp_dir(const char* name) {
    auto d = std::filesystem::temp_directory_path() / (std::string("quant_test_") + name + "_" + std::to_string(random_u64() % 1000000));
    std::filesystem::remove_all(d);
    std::filesystem::create_directories(d);
    return d.string();
}

static Block mine_on(Chainstate& cs, Mempool& mp, const Hash256& payout, uint64_t time_bump = 0) {
    Block b = create_block_template(cs, mp, payout, {'t'});
    b.header.time += time_bump;
    CHECK(mine_header(b.header, cs.params(), 1ULL << 24));
    return b;
}

TEST(mnemonic) {
    std::string m = mnemonic_generate();
    CHECK(mnemonic_valid(m));
    std::string bad = m;
    bad[0] = bad[0] == 'a' ? 'b' : 'a';
    // (may still be a valid word by chance; checksum will almost certainly fail)
    CHECK(!mnemonic_valid(m + " abandon"));
    CHECK(mnemonic_to_master(m, "") == mnemonic_to_master("  " + m + " ", ""));
    CHECK(mnemonic_to_master(m, "") != mnemonic_to_master(m, "x"));
}

TEST(chain_mine_spend_reorg) {
    auto& p = params_for(Network::Regtest);
    std::string dir = temp_dir("chain");
    std::string words = mnemonic_generate();
    Hash256 other_addr;
    Hash256 txid_sent;
    {
        Chainstate cs(p, dir);
        std::string err;
        CHECK(cs.load(&err));
        Mempool mp(cs);
        auto w = Wallet::create(dir + "/w.qwl", p, words, "", "pw", 0, &err);
        CHECK(w != nullptr);
        cs.on_connect.push_back([&](const Block& b, const BlockIndex* i) { w->block_connected(b, i->height); });
        Hash256 payout = w->issued_keys().front()->addr;

        // Mine past coinbase maturity.
        for (int i = 0; i < COINBASE_MATURITY + 5; i++) {
            Block b = mine_on(cs, mp, payout);
            CHECK(cs.accept_block(b, true, &err));
        }
        CHECK(cs.height() == COINBASE_MATURITY + 5);
        Balance bal = w->balance(cs.height());
        CHECK(bal.confirmed == 6 * 50 * COIN);
        CHECK(bal.immature == 99 * 50 * COIN);

        // Send to a fresh key; Falcon-signed tx through the mempool into a block.
        other_addr = keypair_from_seed(blake3((const uint8_t*)"other", 5)).address_hash();
        Transaction tx;
        Amount fee = 0;
        CHECK(w->create_tx({{encode_address(p, 0, other_addr), 7 * COIN + 12345}}, 0, cs.height(), tx, &fee, &err));
        printf("  tx size %zu bytes (core %zu), fee %s QNT\n", tx.full_size(), tx.core_bytes().size(), format_amount(fee).c_str());
        CHECK(mp.accept(tx, &err));
        if (!err.empty()) printf("  mempool: %s\n", err.c_str());
        txid_sent = tx.txid();
        // Double spend must be rejected by the mempool.
        Transaction dbl = tx;
        dbl.outs[0].value -= 1;
        CHECK(!mp.accept(dbl, &err));
        Block b = mine_on(cs, mp, payout);
        CHECK(b.txs.size() == 2);
        CHECK(cs.accept_block(b, true, &err));
        CHECK(mp.size() == 0);
        auto c = cs.coins_for_address(other_addr);
        CHECK(c.size() == 1 && c[0].second.out.value == 7 * COIN + 12345);

        // Tampered signature => block invalid.
        Transaction tx2;
        CHECK(w->create_tx({{encode_address(p, 0, other_addr), COIN}}, 0, cs.height(), tx2, &fee, &err));
        auto& fw = std::get<WitnessFalcon>(tx2.witness[0]);
        fw.sig[fw.sig.size() / 2] ^= 0x55;
        CHECK(!mp.accept(tx2, &err));
        Block bad = create_block_template(cs, mp, payout, {'x'});
        bad.txs.push_back(tx2);
        bad.header.merkle_root = bad.compute_merkle_root();
        bad.header.witness_root = bad.compute_witness_root();
        CHECK(mine_header(bad.header, p, 1ULL << 24));
        int64_t h_before = cs.height();
        cs.accept_block(bad, true, &err);
        CHECK(cs.height() == h_before);

        // Reorg: build a longer side chain from 2 blocks back that doesn't include our tx.
        BlockIndex* fork = cs.at_height(cs.height() - 2);
        Hash256 side_pay = other_addr;
        std::vector<Block> side;
        BlockHeader prevh = fork->header;
        int64_t fh = fork->height;
        for (int i = 0; i < 4; i++) {
            Block sb;
            Transaction cb;
            cb.lock_height = uint64_t(fh + 1 + i);
            cb.extra = {'s', uint8_t(i)};
            cb.outs.push_back(TxOut{block_subsidy(uint64_t(fh + 1 + i)), 0, side_pay});
            sb.txs.push_back(cb);
            sb.header.prev = prevh.hash();
            sb.header.time = prevh.time + 1;
            sb.header.bits = p.genesis_bits;
            sb.header.merkle_root = sb.compute_merkle_root();
            sb.header.witness_root = sb.compute_witness_root();
            CHECK(mine_header(sb.header, p, 1ULL << 24));
            side.push_back(sb);
            prevh = sb.header;
        }
        for (auto& sb : side) cs.accept_block(sb, true, &err);
        CHECK(cs.tip()->hash == side.back().header.hash());
        CHECK(cs.coins_for_address(other_addr).size() == 4); // tx output gone, 4 side rewards
        CHECK(!cs.find_tx_block(txid_sent));
        cs.flush();
    }
    // Restart: state must come back from disk.
    {
        Chainstate cs(p, dir);
        std::string err;
        CHECK(cs.load(&err));
        CHECK(cs.height() == COINBASE_MATURITY + 5 + 1 - 2 + 4);
        CHECK(cs.coins_for_address(other_addr).size() == 4);
        std::string werr;
        auto w = Wallet::open(dir + "/w.qwl", p, "pw", &werr);
        CHECK(w != nullptr);
        CHECK(!Wallet::open(dir + "/w.qwl", p, "wrong", &werr));
        // Same seed on another device derives the same first address.
        auto w2 = Wallet::create(dir + "/w2.qwl", p, words, "", "", 0, &werr);
        CHECK(w2 && w2->issued_keys().front()->addr == w->issued_keys().front()->addr);
    }
    { std::error_code ec; std::filesystem::remove_all(dir, ec); }
}

TEST(sig_dedup_and_backup_key) {
    // Several coins at one address share a single Falcon signature (WitnessRef);
    // the SPHINCS+ backup key can also spend.
    auto& p = params_for(Network::Regtest);
    std::string dir = temp_dir("dedup");
    Chainstate cs(p, dir);
    std::string err;
    CHECK(cs.load(&err));
    Mempool mp(cs);
    auto w = Wallet::create(dir + "/w.qwl", p, mnemonic_generate(), "", "", 0, &err);
    cs.on_connect.push_back([&](const Block& b, const BlockIndex* i) { w->block_connected(b, i->height); });
    Hash256 payout = w->issued_keys().front()->addr;
    for (int i = 0; i < COINBASE_MATURITY + 3; i++) CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));
    Hash256 dest = keypair_from_seed(blake3((const uint8_t*)"d", 1)).address_hash();
    Transaction tx;
    Amount fee;
    CHECK(w->create_tx({{encode_address(p, 0, dest), 120 * COIN}}, 0, cs.height(), tx, &fee, &err));
    CHECK(tx.ins.size() == 3);
    int refs = 0;
    for (auto& wt : tx.witness) refs += std::holds_alternative<WitnessRef>(wt);
    CHECK(refs == 2);
    CHECK(mp.accept(tx, &err));
    printf("  3-input tx: %zu bytes (one shared signature)\n", tx.full_size());
    CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));
    for (int i = 0; i < 2; i++) CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));

    Transaction btx;
    CHECK(w->create_sweep(encode_address(p, 0, dest), 0, cs.height(), btx, &fee, &err, true));
    CHECK(std::holds_alternative<WitnessSphincs>(btx.witness[0]));
    CHECK(mp.accept(btx, &err));
    if (!err.empty()) printf("  backup: %s\n", err.c_str());
    printf("  SPHINCS+ backup sweep: %zu bytes, fee %s\n", btx.full_size(), format_amount(fee).c_str());
    { std::error_code ec; std::filesystem::remove_all(dir, ec); }
}

TEST(difficulty_retarget) {
    // LWMA should raise difficulty when blocks come fast and lower it when slow.
    auto& p = params_for(Network::Test);
    std::vector<HeaderInfo> hist;
    uint32_t bits = p.genesis_bits;
    uint64_t t = 1000000;
    for (int i = 0; i < 200; i++) {
        hist.push_back({t, bits});
        int64_t h = int64_t(hist.size()) - 1;
        bits = next_bits(h, [&](int k) { return hist[size_t(h - k)]; }, p);
        t += 30; // 4x too fast
    }
    CHECK(U256::from_compact(bits) < U256::from_compact(p.genesis_bits));
    U256 fast = U256::from_compact(bits);
    for (int i = 0; i < 200; i++) {
        hist.push_back({t, bits});
        int64_t h = int64_t(hist.size()) - 1;
        bits = next_bits(h, [&](int k) { return hist[size_t(h - k)]; }, p);
        t += 480; // 4x too slow
    }
    CHECK(U256::from_compact(bits) > fast);
    printf("  target ratio after slow blocks: %.2f\n", U256::from_compact(bits).to_double() / fast.to_double());
}

TEST(node_rpc_regtest) {
    NodeConfig cfg;
    cfg.net = Network::Regtest;
    cfg.datadir = temp_dir("node");
    cfg.enable_p2p = false;
    cfg.log_stdout = false;
    {
        Node node(cfg);
        std::string err;
        CHECK(node.start(&err));
        json r = node.rpc("createwallet", json::array());
        CHECK(r.contains("seed_words"));
        node.rpc("generate", json::array({"105"}));
        CHECK(node.rpc("getblockcount", json::array()).get<int64_t>() == 105);
        CHECK(node.rpc("getbalance", json::array()).get<std::string>() == "300.0");
        std::string dest = node.rpc("getnewaddress", json::array({"test"})).get<std::string>();
        std::string txid = node.rpc("send", json::array({dest, "1.5"})).get<std::string>();
        CHECK(txid.size() == 64);
        node.rpc("generate", json::array({"1"}));
        json tx = node.rpc("gettransaction", json::array({txid}));
        CHECK(tx["confirmations"].get<int64_t>() == 1);
        json hist = node.rpc("listtransactions", json::array());
        CHECK(hist.size() >= 2);
        json blk = node.rpc("getblock", json::array({"106"}));
        CHECK(blk["tx_count"].get<int>() == 2);
        node.stop();
    }
    { std::error_code ec; std::filesystem::remove_all(cfg.datadir, ec); }
}

TEST(bench_pow) {
    BlockHeader h;
    h.bits = 0x01010000; // impossible target: pure hashing
    auto t0 = std::chrono::steady_clock::now();
    mine_header(h, params_for(Network::Test), 2'000'000);
    double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    printf("  BLAKE3 PoW: %.2f MH/s per thread\n", 2.0 / s);
}
