// RPC / console commands. Shared by quantd's HTTP server, quant-cli and the desktop console.
#include <algorithm>
#include <map>

#include "consensus/limits.h"
#include "node/node.h"
#include "util/log.h"
#include "wallet/mnemonic.h"

namespace quant {

namespace {

struct Cmd {
    const char* args;
    const char* help;
};

const std::map<std::string, Cmd>& commands() {
    static const std::map<std::string, Cmd> m = {
        {"help", {"[command]", "List commands or show help for one"}},
        {"getinfo", {"", "Node, chain, wallet and network summary"}},
        {"getblockchaininfo", {"", "Chain height, difficulty, supply, disk usage"}},
        {"getblockcount", {"", "Current chain height"}},
        {"getbestblockhash", {"", "Hash of the chain tip"}},
        {"getblockhash", {"height", "Block hash at a height"}},
        {"getblock", {"hash|height [verbose=true]", "Block details (explorer)"}},
        {"gettransaction", {"txid", "Transaction details (explorer; confirmed or mempool)"}},
        {"getaddressinfo", {"address", "Balance and coins of any address"}},
        {"getmempoolinfo", {"", "Mempool size"}},
        {"getrawmempool", {"", "Mempool txids"}},
        {"getpeerinfo", {"", "Connected peers"}},
        {"getnetworkinfo", {"", "DHT / UPnP / LAN discovery status, bandwidth"}},
        {"addnode", {"host[:port]", "Connect to a node manually (and keep reconnecting)"}},
        {"disconnectnode", {"peer_id", "Drop a peer"}},
        {"getmininginfo", {"", "Miner status and network difficulty"}},
        {"setmining", {"threads [address]", "Start mining with N threads (0 = stop)"}},
        {"generate", {"n [address]", "Mine n blocks right now (regtest/testnet helper)"}},
        {"getwalletinfo", {"", "Wallet balance and status"}},
        {"getbalance", {"", "Spendable balance"}},
        {"getnewaddress", {"[label]", "New receiving address"}},
        {"listaddresses", {"", "Wallet addresses"}},
        {"listunspent", {"", "Wallet coins"}},
        {"listtransactions", {"[count=50]", "Wallet history"}},
        {"send", {"address amount [fee_per_kb] [subtract_fee=false]", "Send QNT"}},
        {"sweep", {"address", "Send the whole QNT balance"}},
        {"sendtoken", {"token address amount", "Send a token (token = id or ticker)"}},
        {"gettokenbalances", {"", "Wallet token and pool-share balances"}},
        {"createtoken", {"TICKER \"Name\" supply [decimals=8] [uri]", "Create a token (free apart from the normal tx fee); the whole supply goes to your wallet"}},
        {"listtokens", {"[offset=0] [count=100] [sort=new|liquidity]", "Tokens with their pool price and liquidity"}},
        {"gettoken", {"token", "Token details and pool"}},
        {"getpool", {"token", "QNT/token pool reserves (pending trades included)"}},
        {"quote", {"token buy|sell amount", "Price a trade: buy = spend QNT amount, sell = sell token amount"}},
        {"swap", {"token buy|sell amount [max_slippage_percent=1]", "Trade on the pool"}},
        {"addliquidity", {"token qnt_amount token_amount", "Deposit into the pool (creates it on first deposit); earns the 0.3% trade fee"}},
        {"removeliquidity", {"token shares|all", "Withdraw your pool shares"}},
        {"getaddresscoins", {"address", "Unspent coins (all assets, unconfirmed included) of any address, for external wallets"}},
        {"sendrawtransaction", {"hex", "Broadcast a signed transaction (full encoding, hex)"}},
        {"decoderawtransaction", {"hex", "Decode a transaction"}},
        {"getsnapshotinfo", {"", "State snapshots held and committed (fast sync)"}},
        {"getemission", {"[height]", "Block reward, issued supply and the emission schedule"}},
        {"estimatefee", {"[inputs=1] [outputs=2]", "Fee for a typical transaction at the minimum rate"}},
        {"validateaddress", {"address", "Check an address"}},
        {"createwallet", {"[\"24 words\"] [passphrase] [password]", "Create (or restore from seed words) the wallet"}},
        {"dumpseed", {"confirm", "Show the 24 seed words (pass the word confirm)"}},
        {"walletpassword", {"old new", "Change the wallet file password"}},
        {"addcontact", {"name address", "Address book: add"}},
        {"removecontact", {"name", "Address book: remove"}},
        {"listcontacts", {"", "Address book"}},
        {"stop", {"", "Shut down the node"}},
    };
    return m;
}

std::string arg_str(const json& p, size_t i, const std::string& def = "") {
    if (!p.is_array() || i >= p.size() || p[i].is_null()) return def;
    if (p[i].is_string()) return p[i].get<std::string>();
    return p[i].dump();
}
bool has_arg(const json& p, size_t i) { return p.is_array() && i < p.size() && !p[i].is_null(); }
int64_t arg_int(const json& p, size_t i, int64_t def) {
    if (!has_arg(p, i)) return def;
    if (p[i].is_number_integer()) return p[i].get<int64_t>();
    try { return std::stoll(arg_str(p, i)); } catch (...) { throw RpcError("argument " + std::to_string(i + 1) + " must be a number"); }
}
bool arg_bool(const json& p, size_t i, bool def) {
    if (!has_arg(p, i)) return def;
    if (p[i].is_boolean()) return p[i].get<bool>();
    std::string s = arg_str(p, i);
    return s == "true" || s == "1" || s == "yes";
}
Amount arg_amount(const json& p, size_t i) {
    auto a = parse_amount(arg_str(p, i));
    if (!a) throw RpcError("invalid amount (use up to 10 decimals, e.g. 1.25)");
    return *a;
}

// Amount in base units shown with `dec` decimals (QNT has 10).
std::string format_units(Amount a, int dec) {
    if (dec == 10) return format_amount(a);
    std::string s = std::to_string(a);
    if (dec == 0) return s;
    if (int(s.size()) <= dec) s.insert(0, size_t(dec - int(s.size()) + 1), '0');
    s.insert(s.size() - size_t(dec), ".");
    while (s.back() == '0') s.pop_back();
    if (s.back() == '.') s.pop_back();
    return s;
}
std::optional<Amount> parse_units(const std::string& s, int dec) {
    if (s.empty()) return std::nullopt;
    unsigned __int128 v = 0;
    int frac = -1;
    for (char c : s) {
        if (c == '.') { if (frac >= 0) return std::nullopt; frac = 0; continue; }
        if (c < '0' || c > '9') return std::nullopt;
        if (frac >= 0 && ++frac > dec) return std::nullopt;
        v = v * 10 + unsigned(c - '0');
        if (v > ~uint64_t(0)) return std::nullopt;
    }
    for (int i = frac < 0 ? 0 : frac; i < dec; i++) { v *= 10; if (v > ~uint64_t(0)) return std::nullopt; }
    return Amount(v);
}

} // namespace

std::vector<std::string> Node::rpc_commands() const {
    std::vector<std::string> v;
    for (auto& [k, c] : commands()) v.push_back(k);
    return v;
}

json Node::tx_json(const Transaction& tx, const Hash256* block, int64_t height) {
    json j;
    j["txid"] = tx.txid().hex();
    j["coinbase"] = tx.is_coinbase();
    j["size_core"] = tx.core_bytes().size();
    j["size_witness"] = tx.witness_bytes().size();
    if (block) { j["block"] = block->hex(); j["height"] = height; j["confirmations"] = cs_->height() - height + 1; }
    const StateReader& st = mp_->view();
    json ins = json::array();
    for (size_t i = 0; i < tx.ins.size(); i++) {
        json in;
        in["txid"] = tx.ins[i].prev.txid.hex();
        in["vout"] = tx.ins[i].prev.n;
        if (i < tx.witness.size()) in["signature"] = std::holds_alternative<WitnessFalcon>(tx.witness[i]) ? "falcon-512" : "shared";
        ins.push_back(in);
    }
    j["inputs"] = ins;
    json outs = json::array();
    for (uint32_t n = 0; n < tx.outs.size(); n++) outs.push_back(out_json(tx.outs[n], st, n));
    j["outputs"] = outs;
    json ops = json::array();
    for (auto& op : tx.ops) ops.push_back(op_json(op, st));
    if (!ops.empty()) j["ops"] = ops;
    j["total_qnt_out"] = format_amount(tx.total_qnt_out());
    if (tx.is_coinbase()) j["miner_tag"] = std::string(tx.extra.begin(), tx.extra.end() - std::min<size_t>(8, tx.extra.size()));
    return j;
}

json Node::out_json(const TxOut& o, const StateReader& st, int64_t n) {
    json j;
    if (n >= 0) j["n"] = n;
    j["address"] = encode_address(p_, 0, o.addr);
    j["asset"] = asset_label(o.asset, st);
    if (!o.is_qnt()) j["asset_id"] = o.asset.hex();
    j["amount"] = format_units(o.value, asset_decimals(o.asset, st));
    j["units"] = o.value;
    return j;
}

json Node::op_json(const TxOp& op, const StateReader& st) {
    return std::visit([&](auto& o) -> json {
        using T = std::decay_t<decltype(o)>;
        if constexpr (std::is_same_v<T, OpCreateToken>) {
            return {{"type", "create-token"}, {"ticker", o.ticker}, {"name", o.name}, {"decimals", o.decimals},
                    {"supply", format_units(o.supply, o.decimals)}, {"uri", o.uri}};
        } else {
            int d = asset_decimals(o.token, st);
            std::string tk = asset_label(o.token, st);
            if constexpr (std::is_same_v<T, OpPoolCreate>)
                return {{"type", "pool-create"}, {"token", tk}, {"qnt", format_amount(o.qnt)}, {"tok", format_units(o.tok, d)}, {"shares", o.shares}};
            else if constexpr (std::is_same_v<T, OpAddLiquidity>)
                return {{"type", "add-liquidity"}, {"token", tk}, {"qnt", format_amount(o.qnt)}, {"tok", format_units(o.tok, d)}, {"shares", o.shares}};
            else if constexpr (std::is_same_v<T, OpRemoveLiquidity>)
                return {{"type", "remove-liquidity"}, {"token", tk}, {"shares", o.shares}, {"qnt", format_amount(o.qnt)}, {"tok", format_units(o.tok, d)}};
            else
                return {{"type", o.sell ? "sell" : "buy"}, {"token", tk},
                        {"in", o.sell ? format_units(o.in, d) : format_amount(o.in)},
                        {"out", o.sell ? format_amount(o.out) : format_units(o.out, d)}};
        }
    }, op);
}

int Node::asset_decimals(const Hash256& a, const StateReader& st) {
    if (a.is_zero()) return 10;
    if (auto t = st.token(a)) return t->decimals;
    return 0; // pool shares and unknown assets are whole units
}

std::string Node::asset_label(const Hash256& a, const StateReader& st) {
    if (a.is_zero()) return "QNT";
    if (auto t = st.token(a)) return t->ticker;
    for (auto& p : cs_->all_pools())
        if (pool_share_id(p.token) == a) { auto t = st.token(p.token); return (t ? t->ticker : p.token.hex().substr(0, 8)) + "-QNT-SHARE"; }
    return a.hex().substr(0, 16);
}

json Node::pool_json(const Pool& p, const StateReader& st) {
    auto t = st.token(p.token);
    int d = t ? t->decimals : 0;
    json j;
    j["token"] = p.token.hex();
    j["ticker"] = t ? t->ticker : "";
    j["qnt_reserve"] = format_amount(p.qnt);
    j["token_reserve"] = format_units(p.tok, d);
    j["shares"] = p.shares;
    j["share_id"] = pool_share_id(p.token).hex();
    // Price of one whole token in QNT: (qnt / 10^10) / (tok / 10^d)
    j["price_qnt"] = p.tok ? (double(p.qnt) / 1e10) / (double(p.tok) / std::pow(10.0, d)) : 0.0;
    j["liquidity_qnt"] = 2.0 * double(p.qnt) / 1e10; // both sides valued in QNT
    return j;
}

json Node::token_json(const TokenInfo& t, const StateReader& st) {
    json j;
    j["id"] = t.id.hex();
    j["ticker"] = t.ticker;
    j["name"] = t.name;
    j["decimals"] = t.decimals;
    j["supply"] = format_units(t.supply, t.decimals);
    j["uri"] = t.uri;
    j["created_txid"] = t.create_txid.hex();
    j["created_height"] = t.height;
    if (auto p = st.pool(t.id)) j["pool"] = pool_json(*p, st);
    return j;
}

json Node::block_json(const Block& b, const BlockIndex* idx, bool verbose) {
    json j;
    j["hash"] = idx->hash.hex();
    j["height"] = idx->height;
    j["confirmations"] = cs_->in_active_chain(idx) ? cs_->height() - idx->height + 1 : -1;
    j["prev"] = b.header.prev.hex();
    if (BlockIndex* nx = cs_->at_height(idx->height + 1); nx && cs_->in_active_chain(idx)) j["next"] = nx->hash.hex();
    j["time"] = b.header.time;
    j["bits"] = b.header.bits;
    j["nonce"] = b.header.nonce;
    j["merkle_root"] = b.header.merkle_root.hex();
    j["witness_root"] = b.header.witness_root.hex();
    j["tx_count"] = b.txs.size();
    j["size_core"] = b.core_bytes().size();
    j["signatures_pruned"] = !cs_->have_witness(idx);
    j["difficulty"] = params().pow_limit.to_double() / U256::from_compact(b.header.bits).to_double();
    j["reward"] = format_amount(b.txs.empty() ? 0 : b.txs[0].total_qnt_out());
    j["state_commit"] = b.header.state_commit.is_zero() ? "" : b.header.state_commit.hex();
    if (verbose) {
        json txs = json::array();
        for (auto& t : b.txs) txs.push_back(tx_json(t, &idx->hash, idx->height));
        j["txs"] = txs;
    } else {
        json ids = json::array();
        for (auto& t : b.txs) ids.push_back(t.txid().hex());
        j["txs"] = ids;
    }
    return j;
}

json Node::rpc(const std::string& method, const json& params) {
    const json& p = params.is_array() ? params : json::array();
    auto need_wallet = [&]() -> Wallet& {
        if (!wallet_) throw RpcError("no wallet loaded (use createwallet, or open it in the client)");
        return *wallet_;
    };

    if (method == "help") {
        if (has_arg(p, 0)) {
            auto it = commands().find(arg_str(p, 0));
            if (it == commands().end()) throw RpcError("unknown command");
            return it->first + " " + it->second.args + "\n  " + it->second.help;
        }
        std::string s;
        for (auto& [k, c] : commands()) s += k + " " + c.args + "\n    " + c.help + "\n";
        return s;
    }
    if (method == "stop") { stop_requested_ = true; return "Quant node stopping"; }

    std::lock_guard lock(cs_->mu);
    if (method == "getblockcount") return cs_->height();
    if (method == "getbestblockhash") return cs_->tip()->hash.hex();
    if (method == "getblockchaininfo" || method == "getinfo") {
        ChainStats s = cs_->stats();
        json j;
        j["network"] = p_.name;
        j["height"] = s.height;
        j["headers"] = s.header_height;
        j["best_block"] = s.tip.hex();
        j["difficulty"] = s.difficulty;
        j["syncing"] = cs_->is_initial_sync();
        j["supply"] = format_amount(s.supply);
        j["max_supply"] = format_amount(MAX_MONEY);
        j["block_reward"] = format_amount(block_subsidy(uint64_t(s.height + 1)));
        j["utxos"] = s.utxo_count;
        j["disk_blocks_mb"] = double(s.disk_blocks) / 1e6;
        j["disk_signatures_mb"] = double(s.disk_witness) / 1e6;
        j["disk_headers_mb"] = double(s.disk_headers) / 1e6;
        j["pruning"] = cfg_.prune;
        j["mempool_txs"] = mp_->size();
        if (method == "getinfo") {
            j["version"] = "0.2.0";
            if (p2p_) { j["peers"] = p2p_->peer_count(); }
            j["mining"] = miner_->running();
            j["hashrate"] = miner_->hashrate();
            if (wallet_) j["balance"] = format_amount(wallet_->balance(s.height).confirmed);
            j["wallet"] = wallet_ ? "loaded" : (has_wallet_file() ? "locked" : "none");
        }
        return j;
    }
    if (method == "getblockhash") {
        BlockIndex* b = cs_->at_height(arg_int(p, 0, -1));
        if (!b) throw RpcError("height out of range");
        return b->hash.hex();
    }
    if (method == "getblock") {
        std::string a = arg_str(p, 0);
        BlockIndex* idx = nullptr;
        if (a.size() == 64) { if (auto h = Hash256::from_hex(a)) idx = cs_->lookup(*h); }
        else { try { idx = cs_->at_height(std::stoll(a)); } catch (...) {} }
        if (!idx || !idx->have_data) throw RpcError("block not found");
        Block b;
        if (!cs_->read_block(idx, b, true)) throw RpcError("block data unavailable");
        return block_json(b, idx, arg_bool(p, 1, true));
    }
    if (method == "gettransaction") {
        auto h = Hash256::from_hex(arg_str(p, 0));
        if (!h) throw RpcError("bad txid");
        if (auto tx = mp_->get(*h)) { json j = tx_json(*tx, nullptr, 0); j["confirmations"] = 0; return j; }
        auto bh = cs_->find_tx_block(*h);
        if (!bh) throw RpcError("transaction not found");
        BlockIndex* idx = cs_->lookup(*bh);
        Block b;
        cs_->read_block(idx, b, true);
        for (auto& t : b.txs) if (t.txid() == *h) return tx_json(t, &*bh, idx->height);
        throw RpcError("transaction not found");
    }
    if (method == "getaddressinfo" || method == "validateaddress") {
        uint8_t v; Hash256 a;
        bool ok = decode_address(p_, arg_str(p, 0), v, a);
        json j;
        j["valid"] = ok;
        if (!ok) return j;
        j["version"] = v;
        j["mine"] = wallet_ && wallet_->is_mine(a);
        if (method == "getaddressinfo") {
            Amount bal = 0;
            json coins = json::array();
            const StateReader& sv = mp_->view();
            json tokens = json::array();
            for (auto& [asset, v] : cs_->balances_for_address(a)) {
                if (asset.is_zero()) { bal = v; continue; }
                tokens.push_back({{"asset", asset_label(asset, sv)}, {"asset_id", asset.hex()}, {"amount", format_units(v, asset_decimals(asset, sv))}});
            }
            for (auto& [op, c] : cs_->coins_for_address(a)) {
                json cj = out_json(c.out, sv);
                cj["txid"] = op.txid.hex(); cj["vout"] = op.n; cj["height"] = c.height;
                coins.push_back(cj);
            }
            j["balance"] = format_amount(bal);
            j["tokens"] = tokens;
            j["coins"] = coins;
        }
        return j;
    }
    if (method == "getmempoolinfo") return json{{"txs", mp_->size()}, {"bytes", mp_->bytes()}, {"min_fee_per_kb", format_amount(MIN_RELAY_FEE_PER_KB)}};
    if (method == "getrawmempool") { json a = json::array(); for (auto& h : mp_->txids()) a.push_back(h.hex()); return a; }
    if (method == "getpeerinfo") {
        json a = json::array();
        if (p2p_) for (auto& pi : p2p_->peers())
            a.push_back({{"id", pi.id}, {"addr", pi.addr}, {"inbound", pi.inbound}, {"light_wallet", pi.light}, {"agent", pi.agent},
                         {"height", pi.height}, {"connected_secs", pi.connected_secs}, {"ping_ms", pi.ping_ms},
                         {"bytes_in", pi.bytes_in}, {"bytes_out", pi.bytes_out}, {"downloading", pi.inflight}});
        return a;
    }
    if (method == "getnetworkinfo") {
        if (!p2p_) return json{{"p2p", "disabled"}};
        NetStats s = p2p_->stats();
        return json{{"outbound", s.outbound}, {"inbound", s.inbound}, {"known_addresses", s.known_addrs},
                    {"dht", s.dht_status}, {"upnp", s.upnp_status}, {"lan", s.lan_status},
                    {"external_address", s.external_addr}, {"listening", s.listening},
                    {"bytes_in", s.bytes_in}, {"bytes_out", s.bytes_out}, {"port", cfg_.p2p.port ? cfg_.p2p.port : p_.p2p_port}};
    }
    if (method == "addnode") { if (!p2p_) throw RpcError("p2p disabled"); p2p_->add_node(arg_str(p, 0)); return "connecting to " + arg_str(p, 0); }
    if (method == "disconnectnode") { if (p2p_) p2p_->disconnect(uint64_t(arg_int(p, 0, 0))); return "ok"; }
    if (method == "getmininginfo") {
        ChainStats s = cs_->stats();
        return json{{"mining", miner_->running()}, {"threads", miner_->threads()}, {"hashrate", miner_->hashrate()},
                    {"blocks_found", miner_->blocks_found()}, {"difficulty", s.difficulty}, {"height", s.height},
                    {"reward", format_amount(block_subsidy(uint64_t(s.height + 1)))},
                    {"payout_address", miner_->running() ? encode_address(p_, 0, miner_->payout()) : ""},
                    {"network_hashrate_est", s.difficulty * std::pow(2.0, 256 - p_.pow_limit.bits()) / TARGET_SPACING}};
    }
    if (method == "setmining") {
        int threads = int(arg_int(p, 0, 0));
        if (threads <= 0) { miner_->stop(); return "mining stopped"; }
        std::string err;
        if (!start_mining(threads, arg_str(p, 1), &err)) throw RpcError(err);
        return "mining with " + std::to_string(threads) + " threads";
    }
    if (method == "generate") {
        int64_t n = arg_int(p, 0, 1);
        Hash256 payout;
        std::string addr = arg_str(p, 1);
        uint8_t v;
        if (!addr.empty()) { if (!decode_address(p_, addr, v, payout)) throw RpcError("bad address"); }
        else payout = need_wallet().issued_keys().front()->addr;
        json hashes = json::array();
        for (int64_t i = 0; i < n; i++) {
            Block b = create_block_template(*cs_, *mp_, payout, {'g', 'e', 'n'});
            while (!mine_header(b.header, p_, 1ULL << 22)) b.header.time = uint64_t(std::max<int64_t>(int64_t(b.header.time), now_seconds()));
            std::string why;
            if (!cs_->accept_block(b, true, &why)) throw RpcError("generated block rejected: " + why);
            hashes.push_back(b.header.hash().hex());
        }
        return hashes;
    }
    if (method == "createwallet") {
        std::string words = arg_str(p, 0);
        bool restored = !words.empty();
        if (!restored) words = mnemonic_generate();
        std::string err;
        if (!create_wallet(words, arg_str(p, 1), arg_str(p, 2), restored, &err)) throw RpcError(err);
        return json{{"seed_words", words}, {"address", wallet_->address_string(wallet_->issued_keys().front()->addr)},
                    {"warning", "Write these 24 words down offline. Anyone with them can spend your QNT."}};
    }

    // ---- wallet commands
    if (method == "getwalletinfo" || method == "getbalance") {
        Wallet& w = need_wallet();
        Balance b = w.balance(cs_->height());
        if (method == "getbalance") return format_amount(b.confirmed);
        return json{{"confirmed", format_amount(b.confirmed)}, {"unconfirmed", format_amount(b.unconfirmed)},
                    {"immature", format_amount(b.immature)}, {"pending_send", format_amount(b.locked)},
                    {"addresses", w.issued_keys().size()}, {"coins", w.coins().size()},
                    {"synced_height", w.synced_height}, {"receive_address", w.address_string(w.issued_keys().back()->addr)}};
    }
    if (method == "getnewaddress") { std::string a = need_wallet().new_address(arg_str(p, 0)); wallet_->save(); return a; }
    if (method == "listaddresses") {
        json a = json::array();
        Wallet& w = need_wallet();
        for (auto* k : w.issued_keys()) {
            Amount bal = cs_->balances_for_address(k->addr)[QNT_ASSET];
            a.push_back({{"address", w.address_string(k->addr)}, {"label", k->label}, {"index", k->index}, {"balance", format_amount(bal)}});
        }
        return a;
    }
    if (method == "listunspent") {
        json a = json::array();
        Wallet& w = need_wallet();
        for (auto& c : w.coins())
            a.push_back({{"txid", c.op.txid.hex()}, {"vout", c.op.n}, {"address", w.address_string(c.out.addr)},
                         {"amount", format_amount(c.out.value)}, {"height", c.height}, {"coinbase", c.coinbase}, {"locked", c.locked}});
        return a;
    }
    if (method == "listtransactions") {
        json a = json::array();
        auto hist = need_wallet().history();
        size_t n = size_t(arg_int(p, 0, 50));
        for (size_t i = 0; i < hist.size() && i < n; i++) {
            auto& t = hist[i];
            std::string amt = (t.delta < 0 ? "-" : "") + format_amount(Amount(t.delta < 0 ? -t.delta : t.delta));
            a.push_back({{"txid", t.txid.hex()}, {"height", t.height}, {"time", t.time}, {"amount", amt},
                         {"fee", format_amount(t.fee)}, {"type", t.coinbase ? "mined" : t.delta < 0 ? "sent" : "received"},
                         {"counterparty", t.counterparty}, {"note", t.note},
                         {"confirmations", t.height < 0 ? 0 : cs_->height() - t.height + 1}});
        }
        return a;
    }
    if (method == "send") {
        need_wallet();
        Amount fee_kb = has_arg(p, 2) ? arg_amount(p, 2) : 0;
        return send({{arg_str(p, 0), arg_amount(p, 1), QNT_ASSET}}, fee_kb, arg_bool(p, 3, false), "");
    }
    if (method == "sweep") {
        Wallet& w = need_wallet();
        Transaction tx;
        Amount fee;
        std::string err;
        if (!w.create_sweep(arg_str(p, 0), 0, cs_->height(), tx, &fee, &err)) throw RpcError(err);
        if (!mp_->accept(tx, &err)) throw RpcError("rejected: " + err);
        w.tx_broadcast(tx, "sweep");
        if (p2p_) p2p_->broadcast_tx(tx);
        return json{{"txid", tx.txid().hex()}, {"fee", format_amount(fee)}, {"size", tx.full_size()}};
    }
    if (method == "estimatefee") {
        size_t ins = size_t(arg_int(p, 0, 1)), outs = size_t(arg_int(p, 1, 2));
        size_t sz = 8 + ins * 37 + outs * 42 + 3 + 1684 + (ins - 1) * 4;
        return json{{"fee", format_amount(Amount(sz) * MIN_RELAY_FEE_PER_KB / 1000)}, {"bytes", sz}, {"fee_per_kb", format_amount(MIN_RELAY_FEE_PER_KB)}};
    }
    if (method == "dumpseed") {
        if (arg_str(p, 0) != "confirm") throw RpcError("this reveals your seed words; run: dumpseed confirm");
        return need_wallet().mnemonic();
    }
    if (method == "walletpassword") {
        if (!need_wallet().change_password(arg_str(p, 0), arg_str(p, 1))) throw RpcError("old password is wrong");
        return "password changed";
    }
    if (method == "addcontact") {
        Wallet& w = need_wallet();
        uint8_t v; Hash256 a;
        if (!decode_address(p_, arg_str(p, 1), v, a)) throw RpcError("invalid address");
        w.contacts.push_back({arg_str(p, 0), arg_str(p, 1)});
        w.save();
        return "added";
    }
    if (method == "removecontact") {
        Wallet& w = need_wallet();
        std::string n = arg_str(p, 0);
        w.contacts.erase(std::remove_if(w.contacts.begin(), w.contacts.end(), [&](auto& c) { return c.name == n; }), w.contacts.end());
        w.save();
        return "removed";
    }
    if (method == "listcontacts") {
        json a = json::array();
        for (auto& c : need_wallet().contacts) a.push_back({{"name", c.name}, {"address", c.address}});
        return a;
    }
    // ---- tokens / pools (reads use the mempool view: pending trades included)
    const StateReader& st = mp_->view();
    auto broadcast_built = [&](const Transaction& tx, const std::string& note, Amount fee, json extra) {
        std::string id = broadcast(tx, note);
        extra["txid"] = id;
        extra["fee"] = format_amount(fee);
        return extra;
    };
    auto tip = [&] { return cs_->height(); };
    auto fee_kb = Amount(0);
    if (method == "listtokens") {
        int64_t off = arg_int(p, 0, 0), cnt = std::clamp<int64_t>(arg_int(p, 1, 100), 1, 1000);
        std::string sort = arg_str(p, 2, "new");
        auto toks = cs_->all_tokens();
        if (sort == "liquidity") {
            std::sort(toks.begin(), toks.end(), [&](auto& a, auto& b) {
                auto pa = st.pool(a.id), pb = st.pool(b.id);
                return (pa ? pa->qnt : 0) > (pb ? pb->qnt : 0);
            });
        } else {
            std::sort(toks.begin(), toks.end(), [](auto& a, auto& b) { return a.height > b.height; });
        }
        json a = json::array();
        for (int64_t i = off; i < int64_t(toks.size()) && i < off + cnt; i++) a.push_back(token_json(toks[size_t(i)], st));
        return json{{"total", toks.size()}, {"tokens", a}};
    }
    if (method == "gettoken") {
        auto t = st.token(resolve_token(arg_str(p, 0)));
        return token_json(*t, st);
    }
    if (method == "getpool") {
        Hash256 id = resolve_token(arg_str(p, 0));
        auto pl = st.pool(id);
        if (!pl) throw RpcError("no pool for this token yet (create it with addliquidity)");
        return pool_json(*pl, st);
    }
    if (method == "quote" || method == "swap") {
        Hash256 id = resolve_token(arg_str(p, 0));
        std::string side = arg_str(p, 1);
        if (side != "buy" && side != "sell") throw RpcError("side must be buy or sell");
        bool sell = side == "sell";
        auto pl = st.pool(id);
        if (!pl) throw RpcError("no pool for this token yet");
        int d = asset_decimals(id, st);
        auto in = parse_units(arg_str(p, 2), sell ? d : 10);
        if (!in || !*in) throw RpcError("invalid amount");
        Amount rin = sell ? pl->tok : pl->qnt, rout = sell ? pl->qnt : pl->tok;
        Amount out = amm_quote(*in, rin, rout);
        if (!out) throw RpcError("amount too small");
        double spot = double(rout) / double(rin), exec = double(out) / double(*in);
        double impact = spot > 0 ? (1.0 - exec / spot) * 100.0 : 0;
        json q{{"side", side}, {"in", sell ? format_units(*in, d) : format_amount(*in)},
               {"out", sell ? format_amount(out) : format_units(out, d)}, {"price_impact_percent", impact},
               {"pool_fee_percent", double(POOL_FEE_BPS) / 100.0}};
        if (method == "quote") return q;
        double slip = has_arg(p, 3) ? std::stod(arg_str(p, 3)) : 1.0;
        if (slip < 0 || slip > 50) throw RpcError("max_slippage_percent must be 0-50");
        Amount min_out = Amount(double(out) * (1.0 - slip / 100.0));
        if (!min_out) min_out = 1;
        Transaction tx; Amount fee; std::string err;
        if (!need_wallet().swap(id, sell, *in, min_out, fee_kb, tip(), tx, &fee, &err)) throw RpcError(err);
        q["min_out"] = sell ? format_amount(min_out) : format_units(min_out, d);
        return broadcast_built(tx, side + " " + asset_label(id, st), fee, q);
    }
    if (method == "createtoken") {
        OpCreateToken t;
        t.ticker = arg_str(p, 0);
        std::transform(t.ticker.begin(), t.ticker.end(), t.ticker.begin(), ::toupper);
        t.name = arg_str(p, 1);
        t.decimals = uint8_t(std::clamp<int64_t>(arg_int(p, 3, 8), 0, 255));
        auto s = parse_units(arg_str(p, 2), t.decimals);
        if (!s || !*s) throw RpcError("invalid supply");
        t.supply = *s;
        t.uri = arg_str(p, 4);
        Transaction tx; Amount fee; Hash256 id; std::string err;
        if (!need_wallet().create_token(t, fee_kb, tip(), tx, &id, &fee, &err)) throw RpcError(err);
        return broadcast_built(tx, "create " + t.ticker, fee, json{{"token", id.hex()}, {"ticker", t.ticker}});
    }
    if (method == "addliquidity") {
        Hash256 id = resolve_token(arg_str(p, 0));
        int d = asset_decimals(id, st);
        auto q = parse_units(arg_str(p, 1), 10), t = parse_units(arg_str(p, 2), d);
        if (!q || !t) throw RpcError("invalid amount");
        auto pl = st.pool(id);
        Transaction tx; Amount fee, shares; std::string err;
        if (!need_wallet().add_liquidity(id, *q, *t, pl, fee_kb, tip(), tx, &shares, &fee, &err)) throw RpcError(err);
        return broadcast_built(tx, "add liquidity " + asset_label(id, st), fee, json{{"shares", shares}, {"new_pool", !pl}});
    }
    if (method == "removeliquidity") {
        Hash256 id = resolve_token(arg_str(p, 0));
        auto pl = st.pool(id);
        if (!pl) throw RpcError("no pool for this token");
        Amount shares;
        if (arg_str(p, 1) == "all") {
            auto b = need_wallet().token_balances();
            shares = b[pool_share_id(id)];
        } else {
            shares = Amount(arg_int(p, 1, 0));
        }
        Transaction tx; Amount fee, q, t; std::string err;
        if (!need_wallet().remove_liquidity(id, shares, *pl, fee_kb, tip(), tx, &q, &t, &fee, &err)) throw RpcError(err);
        int d = asset_decimals(id, st);
        return broadcast_built(tx, "remove liquidity " + asset_label(id, st), fee,
                               json{{"qnt", format_amount(q)}, {"tok", format_units(t, d)}, {"shares", shares}});
    }
    if (method == "sendtoken") {
        Hash256 id = resolve_token(arg_str(p, 0));
        auto amt = parse_units(arg_str(p, 2), asset_decimals(id, st));
        if (!amt || !*amt) throw RpcError("invalid amount");
        need_wallet();
        return send({{arg_str(p, 1), *amt, id}}, 0, false, "");
    }
    if (method == "gettokenbalances") {
        json a = json::array();
        for (auto& [asset, v] : need_wallet().token_balances())
            a.push_back({{"asset", asset_label(asset, st)}, {"asset_id", asset.hex()}, {"amount", format_units(v, asset_decimals(asset, st))}, {"units", v}});
        return a;
    }
    if (method == "getaddresscoins") {
        uint8_t v; Hash256 a;
        if (!decode_address(p_, arg_str(p, 0), v, a)) throw RpcError("invalid address");
        json coins = json::array();
        for (auto& [op, c] : cs_->coins_for_address(a)) {
            if (mp_->spends(op)) continue;
            json j = out_json(c.out, st);
            j["txid"] = op.txid.hex(); j["vout"] = op.n; j["height"] = c.height; j["coinbase"] = c.coinbase;
            j["mature"] = !c.coinbase || cs_->height() + 1 >= int64_t(c.height) + COINBASE_MATURITY;
            coins.push_back(j);
        }
        for (auto* e : mp_->all())
            for (uint32_t i = 0; i < e->tx.outs.size(); i++)
                if (e->tx.outs[i].addr == a && !mp_->spends(OutPoint{e->txid, i})) {
                    json j = out_json(e->tx.outs[i], st);
                    j["txid"] = e->txid.hex(); j["vout"] = i; j["height"] = -1; j["coinbase"] = false; j["mature"] = true;
                    coins.push_back(j);
                }
        return json{{"address", arg_str(p, 0)}, {"coins", coins}, {"tip", cs_->height()}, {"genesis", p_.genesis_hash.hex()},
                    {"min_fee_per_kb", MIN_RELAY_FEE_PER_KB}};
    }
    if (method == "sendrawtransaction" || method == "decoderawtransaction") {
        auto raw = hex_decode(arg_str(p, 0));
        if (!raw) throw RpcError("bad hex");
        Transaction tx;
        try { Reader r(*raw); tx = Transaction::read_full(r); if (!r.empty()) throw SerializeError("trailing data"); }
        catch (const std::exception& e) { throw RpcError(std::string("cannot decode: ") + e.what()); }
        if (method == "decoderawtransaction") return tx_json(tx, nullptr, 0);
        std::string err;
        if (!mp_->accept(tx, &err)) throw RpcError("transaction rejected: " + err);
        if (p2p_) p2p_->broadcast_tx(tx);
        return tx.txid().hex();
    }
    if (method == "getsnapshotinfo") {
        json j;
        auto best = cs_->best_snapshot_file();
        j["serving"] = best ? best->first.hex() : "";
        j["interval_blocks"] = p_.snapshot_interval;
        j["commit_delay_blocks"] = p_.snapshot_delay;
        int64_t next = (cs_->height() / p_.snapshot_interval + 1) * p_.snapshot_interval;
        j["next_snapshot_height"] = next;
        ChainStats s = cs_->stats();
        j["disk_snapshots_mb"] = double(s.disk_snapshots) / 1e6;
        return j;
    }
    if (method == "getemission") {
        int64_t h = arg_int(p, 0, cs_->height() + 1);
        if (h < 0) throw RpcError("bad height");
        return json{{"height", h}, {"reward", format_amount(block_subsidy(uint64_t(h)))},
                    {"issued_through_height", format_amount(issued_through(uint64_t(h)))},
                    {"tail_reward", format_amount(TAIL_SUBSIDY)}, {"curve", format_amount(EMISSION_CURVE)},
                    {"block_time_seconds", TARGET_SPACING}, {"premine", "0"}, {"developer_fee", "0"}};
    }
    throw RpcError("unknown command '" + method + "' (try: help)");
}

} // namespace quant

namespace quant {
// A token is named by its 64-hex id or its ticker (tickers aren't unique: the oldest wins,
// and the answer says so when several share it).
Hash256 Node::resolve_token(const std::string& s) {
    const StateReader& st = mp_->view();
    if (s.size() == 64) {
        auto h = Hash256::from_hex(s);
        if (h && st.token(*h)) return *h;
        throw RpcError("unknown token id");
    }
    std::string up = s;
    std::transform(up.begin(), up.end(), up.begin(), ::toupper);
    std::optional<TokenInfo> best;
    int n = 0;
    for (auto& t : cs_->all_tokens())
        if (t.ticker == up) { n++; if (!best || t.height < best->height) best = t; }
    if (!best) throw RpcError("unknown token '" + s + "' (use its id or ticker)");
    if (n > 1) logf("ticker %s is used by %d tokens; using the oldest (%s)", up.c_str(), n, best->id.hex().c_str());
    return best->id;
}
} // namespace quant
