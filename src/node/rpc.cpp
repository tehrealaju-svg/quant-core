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
        {"sweep", {"address [use_backup_key=false]", "Send the whole balance (use_backup_key signs with SPHINCS+)"}},
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
    json ins = json::array();
    Amount in_total = 0;
    for (size_t i = 0; i < tx.ins.size(); i++) {
        json in;
        in["txid"] = tx.ins[i].prev.txid.hex();
        in["vout"] = tx.ins[i].prev.n;
        if (i < tx.witness.size()) {
            const Witness& w = tx.witness[i];
            in["signature"] = std::holds_alternative<WitnessFalcon>(w) ? "falcon-512"
                              : std::holds_alternative<WitnessSphincs>(w) ? "sphincs+ (backup key)" : "shared";
        }
        ins.push_back(in);
    }
    j["inputs"] = ins;
    json outs = json::array();
    for (uint32_t n = 0; n < tx.outs.size(); n++) {
        outs.push_back({{"n", n}, {"address", encode_address(p_, tx.outs[n].addr_ver, tx.outs[n].addr)},
                        {"amount", format_amount(tx.outs[n].value)}});
    }
    j["outputs"] = outs;
    j["total_out"] = format_amount(tx.total_out());
    if (tx.is_coinbase()) j["miner_tag"] = std::string(tx.extra.begin(), tx.extra.end() - std::min<size_t>(8, tx.extra.size()));
    (void)in_total;
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
    j["reward"] = format_amount(b.txs.empty() ? 0 : b.txs[0].total_out());
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
            j["version"] = "0.1.0";
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
            for (auto& [op, c] : cs_->coins_for_address(a)) {
                bal += c.out.value;
                coins.push_back({{"txid", op.txid.hex()}, {"vout", op.n}, {"amount", format_amount(c.out.value)}, {"height", c.height}});
            }
            j["balance"] = format_amount(bal);
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
            Amount bal = 0;
            for (auto& [op, c] : cs_->coins_for_address(k->addr)) bal += c.out.value;
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
        return send({{arg_str(p, 0), arg_amount(p, 1)}}, fee_kb, arg_bool(p, 3, false), "");
    }
    if (method == "sweep") {
        Wallet& w = need_wallet();
        Transaction tx;
        Amount fee;
        std::string err;
        if (!w.create_sweep(arg_str(p, 0), 0, cs_->height(), tx, &fee, &err, arg_bool(p, 1, false))) throw RpcError(err);
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
    throw RpcError("unknown command '" + method + "' (try: help)");
}

} // namespace quant
