// Tokens, pools and state snapshots on a private regtest chain.

TEST(tokens_and_pool_rpc) {
    NodeConfig cfg;
    cfg.net = Network::Regtest;
    cfg.datadir = temp_dir("tokens");
    cfg.enable_p2p = false;
    cfg.log_stdout = false;
    {
        Node node(cfg);
        std::string err;
        CHECK(node.start(&err));
        node.rpc("createwallet", json::array());
        node.rpc("generate", json::array({"130"}));
        auto rpc = [&](const char* m, json a) {
            try { return node.rpc(m, a); } catch (const std::exception& e) { printf("  %s: %s\n", m, e.what()); CHECK(false); return json(); }
        };
        json ct = rpc("createtoken", json::array({"doge2", "Doge Two", "1000000", "8", "https://example.com/doge.png"}));
        std::string id = ct["token"].get<std::string>();
        Hash256 tid = *Hash256::from_hex(id);
        CHECK(ct["ticker"] == "DOGE2");
        node.rpc("generate", json::array({"1"}));
        json tb = rpc("gettokenbalances", json::array());
        CHECK(tb.size() == 1 && tb[0]["amount"] == "1000000");

        // Open the pool: 100 QNT + 500,000 DOGE2 => price 0.0002 QNT.
        json al = rpc("addliquidity", json::array({"DOGE2", "100", "500000"}));
        CHECK(al["new_pool"] == true);
        node.rpc("generate", json::array({"1"}));
        json pool = rpc("getpool", json::array({id}));
        CHECK(pool["qnt_reserve"] == "100.0");
        CHECK(std::abs(pool["price_qnt"].get<double>() - 0.0002) < 1e-12);

        // Buy with 10 QNT, then sell some back; both go through the mempool view in order.
        json q = rpc("quote", json::array({"DOGE2", "buy", "10"}));
        json buy = rpc("swap", json::array({"DOGE2", "buy", "10", "1"}));
        CHECK(buy["txid"].get<std::string>().size() == 64);
        json pool2 = rpc("getpool", json::array({"DOGE2"})); // pending trade already visible
        CHECK(pool2["qnt_reserve"] == "110.0");
        json sell = rpc("swap", json::array({"DOGE2", "sell", "20000", "2"}));
        CHECK(node.mempool().size() == 2);
        node.rpc("generate", json::array({"1"}));
        CHECK(node.mempool().size() == 0);
        printf("  buy 10 QNT -> %s DOGE2 (impact %.2f%%); sell 20000 -> %s QNT\n", q["out"].get<std::string>().c_str(),
               q["price_impact_percent"].get<double>(), sell["out"].get<std::string>().c_str());

        // Asking for more than the pool gives is rejected.
        auto pl = node.mempool().view().pool(tid);
        CHECK(pl.has_value());
        Transaction tx; Amount fee;
        Amount fair = amm_quote(COIN, pl->qnt, pl->tok);
        CHECK(node.wallet()->swap(tid, false, COIN, fair + 1, 0, node.chain().height(), tx, &fee, &err));
        CHECK(!node.mempool().accept(tx, &err));
        CHECK(err == "swap-price-moved");

        // Withdraw all liquidity (the 1000 locked shares stay in the pool forever).
        rpc("removeliquidity", json::array({"DOGE2", "all"}));
        node.rpc("generate", json::array({"1"}));
        json pool3 = rpc("getpool", json::array({"DOGE2"}));
        CHECK(pool3["shares"].get<uint64_t>() == MIN_LIQUIDITY);

        // Send tokens to another address; explorer views.
        std::string to = rpc("getnewaddress", json::array()).get<std::string>();
        std::string stx = rpc("sendtoken", json::array({"DOGE2", to, "123.45"})).get<std::string>();
        node.rpc("generate", json::array({"1"}));
        json ai = rpc("getaddressinfo", json::array({to}));
        CHECK(ai["tokens"].size() == 1 && ai["tokens"][0]["amount"] == "123.45");
        json lt = rpc("listtokens", json::array());
        CHECK(lt["total"] == 1);
        json gt = rpc("gettransaction", json::array({stx}));
        CHECK(gt["confirmations"] == 1);

        // Tokens can't be created from nothing: paying out more DOGE2 than spent fails.
        Transaction forge;
        CHECK(node.wallet()->create_tx({{to, 5, tid}}, 0, node.chain().height(), forge, &fee, &err));
        for (auto& o : forge.outs) if (o.asset == tid && o.value == 5) o.value = 6;
        LedgerView lv(node.chain());
        TxResult tr = lv.apply(forge, uint64_t(node.chain().height() + 1), node.params().genesis_hash, false);
        CHECK(!tr.ok && tr.reason.find("token-not-balanced") == 0);
        node.stop();
    }
    {
        // Restart: tokens and pools survive.
        Node node(cfg);
        std::string err;
        CHECK(node.start(&err));
        json lt = node.rpc("listtokens", json::array());
        CHECK(lt["total"] == 1 && lt["tokens"][0].contains("pool"));
        node.stop();
    }
    { std::error_code ec; std::filesystem::remove_all(cfg.datadir, ec); }
}

static Block side_block(Chainstate& cs, const BlockHeader& prevh, int64_t height, const Hash256& payout, uint8_t tag) {
    auto& p = cs.params();
    Block sb;
    Transaction cb;
    cb.lock_height = uint64_t(height);
    cb.extra = {'z', tag};
    cb.outs.push_back(TxOut{block_subsidy(cb.lock_height), QNT_ASSET, payout});
    sb.txs.push_back(cb);
    sb.header.prev = prevh.hash();
    sb.header.time = prevh.time + 1;
    sb.header.bits = p.genesis_bits;
    sb.header.state_commit = cs.commit_for_next(cs.lookup(sb.header.prev));
    sb.header.merkle_root = sb.compute_merkle_root();
    sb.header.witness_root = sb.compute_witness_root();
    CHECK(mine_header(sb.header, p, 1ULL << 24));
    return sb;
}

TEST(token_reorg_undo) {
    // Blocks that create a token and open its pool are reorganized away: both must vanish.
    auto& p = params_for(Network::Regtest);
    std::string dir = temp_dir("tokreorg");
    Chainstate cs(p, dir);
    std::string err;
    CHECK(cs.load(&err));
    Mempool mp(cs);
    auto w = Wallet::create(dir + "/w.qwl", p, mnemonic_generate(), "", "", 0, &err);
    cs.on_connect.push_back([&](const Block& b, const BlockIndex* i) { w->block_connected(b, i->height); });
    cs.on_disconnect.push_back([&](const Block& b, const BlockIndex* i) { w->block_disconnected(b, i->height); });
    Hash256 payout = w->issued_keys().front()->addr;
    for (int i = 0; i < COINBASE_MATURITY + 10; i++) CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));
    BlockIndex* fork = cs.tip();
    Transaction tx; Amount fee; Hash256 id;
    CHECK(w->create_token(OpCreateToken{"PEPE", "Pepe", 0, 1000000, ""}, 0, cs.height(), tx, &id, &fee, &err));
    CHECK(mp.accept(tx, &err));
    w->tx_broadcast(tx, "");
    CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));
    CHECK(cs.token(id).has_value());
    Transaction ptx; Amount shares;
    CHECK(w->add_liquidity(id, 10 * COIN, 400000, std::nullopt, 0, cs.height(), ptx, &shares, &fee, &err));
    CHECK(mp.accept(ptx, &err));
    CHECK(cs.accept_block(mine_on(cs, mp, payout), true, &err));
    CHECK(cs.pool(id).has_value());
    BlockHeader prevh = fork->header;
    for (int i = 0; i < 3; i++) {
        Block sb = side_block(cs, prevh, fork->height + 1 + i, payout, uint8_t(i));
        cs.accept_block(sb, true, &err);
        prevh = sb.header;
    }
    CHECK(cs.tip()->hash == prevh.hash());
    CHECK(!cs.token(id).has_value());
    CHECK(!cs.pool(id).has_value());
    CHECK(cs.all_tokens().empty());
    { std::error_code ec; std::filesystem::remove_all(dir, ec); }
}

TEST(snapshot_fast_sync) {
    // Node A builds a chain with token activity past a snapshot commitment; fresh node B takes
    // the headers, loads A's committed snapshot, then only downloads the blocks after it.
    auto& p = params_for(Network::Regtest);
    std::string da = temp_dir("snapA"), db = temp_dir("snapB");
    int64_t final_h = 2 * p.snapshot_interval + p.snapshot_delay + 3;
    {
        Chainstate a(p, da);
        std::string err;
        CHECK(a.load(&err));
        Mempool mp(a);
        auto w = Wallet::create(da + "/w.qwl", p, mnemonic_generate(), "", "", 0, &err);
        a.on_connect.push_back([&](const Block& b, const BlockIndex* i) { w->block_connected(b, i->height); });
        Hash256 payout = w->issued_keys().front()->addr;
        for (int i = 0; i < COINBASE_MATURITY + 2; i++) CHECK(a.accept_block(mine_on(a, mp, payout), true, &err));
        Transaction tx; Amount fee; Hash256 id;
        CHECK(w->create_token(OpCreateToken{"SNAP", "Snapshot Coin", 2, 50000, ""}, 0, a.height(), tx, &id, &fee, &err));
        CHECK(mp.accept(tx, &err));
        w->tx_broadcast(tx, "");
        while (a.height() < final_h) CHECK(a.accept_block(mine_on(a, mp, payout), true, &err));
        int64_t snap_h = 2 * p.snapshot_interval;
        BlockIndex* commit = a.at_height(snap_h + p.snapshot_delay);
        CHECK(!commit->header.state_commit.is_zero());
        CHECK(a.at_height(snap_h + p.snapshot_delay + 1)->header.state_commit.is_zero());
        auto best = a.best_snapshot_file();
        CHECK(best && best->first == a.at_height(snap_h)->hash);

        Chainstate b(p, db);
        CHECK(b.load(&err));
        for (int64_t h = 1; h <= a.height(); h++) CHECK(b.accept_header(a.at_height(h)->header, &err) == Chainstate::HeaderResult::Ok);
        Bytes snap;
        CHECK(a.read_snapshot_file(best->first, snap));
        Bytes tampered = snap;
        tampered[tampered.size() / 2] ^= 1;
        CHECK(!b.load_snapshot_bytes(tampered, &err));
        CHECK(err == "hash-mismatch");
        CHECK(b.load_snapshot_bytes(snap, &err));
        CHECK(b.height() == snap_h);
        for (int64_t h = snap_h + 1; h <= a.height(); h++) {
            Block blk;
            CHECK(a.read_block(a.at_height(h), blk, true));
            CHECK(b.accept_block(blk, true, &err));
        }
        CHECK(b.tip()->hash == a.tip()->hash);
        CHECK(Chainstate::state_hash(b.serialize_state()) == Chainstate::state_hash(a.serialize_state()));
        CHECK(b.token(id).has_value());
        printf("  snapshot at %lld: %zu bytes; B connected %lld blocks instead of %lld\n", (long long)snap_h, snap.size(),
               (long long)(a.height() - snap_h), (long long)a.height());
        b.flush();
    }
    {
        // B restarts from disk as a snapshot-based node.
        Chainstate b(p, db);
        std::string err;
        CHECK(b.load(&err));
        CHECK(b.height() == final_h);
    }
    std::error_code ec;
    std::filesystem::remove_all(da, ec);
    std::filesystem::remove_all(db, ec);
}

TEST(p2p_snapshot_sync) {
    // Over real sockets: fresh node B joins A and starts from A's committed snapshot.
    auto mk = [](const char* name, uint16_t port) {
        NodeConfig c;
        c.net = Network::Regtest;
        c.datadir = temp_dir(name);
        c.log_stdout = false;
        c.p2p.port = port;
        c.p2p.dht = c.p2p.lan = c.p2p.upnp = false;
        return c;
    };
    NodeConfig ca = mk("p2pA", 27601), cb = mk("p2pB", 27602);
    cb.p2p.addnodes = {"127.0.0.1:27601"};
    {
        Node a(ca);
        std::string err;
        CHECK(a.start(&err));
        a.rpc("createwallet", json::array());
        a.rpc("generate", json::array({"112"}));
        Node b(cb);
        CHECK(b.start(&err));
        for (int i = 0; i < 100 && b.chain().height() < 112; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        CHECK(b.chain().height() == 112);
        CHECK(b.chain().tip()->hash == a.chain().tip()->hash);
        BlockIndex* old = b.chain().at_height(50);
        CHECK(old && !old->have_data); // never downloaded: came from the snapshot at 100
        b.stop();
        a.stop();
    }
    std::error_code ec;
    std::filesystem::remove_all(ca.datadir, ec);
    std::filesystem::remove_all(cb.datadir, ec);
}
