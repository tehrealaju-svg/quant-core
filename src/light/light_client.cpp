#include "light/light_client.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>

#include "consensus/limits.h"
#include "consensus/pow.h"
#include "crypto/hash.h"
#include "crypto/random.h"
#include "net/dht.h"
#include "util/log.h"

namespace fs = std::filesystem;

namespace quant {

struct LightClient::Peer {
    sock_t s = BAD_SOCK;
    NetAddr addr;
    FrameReader rx;
    VersionMsg ver;
    explicit Peer(const ChainParams& p) : rx(p) {}
    ~Peer() { sock_close(s); }
};

LightClient::LightClient(const ChainParams& p, const std::string& dir) : p_(p), dir_(dir) {
    std::error_code ec;
    fs::create_directories(dir_, ec);
    nonce_ = random_u64();
    net_init();
    load_headers();
}

LightClient::~LightClient() { disconnect_all(); }

void LightClient::disconnect_all() { peers_.clear(); }

std::vector<std::string> LightClient::peer_names() const {
    std::vector<std::string> v;
    for (auto& p : peers_) v.push_back(p->addr.str() + " (" + p->ver.agent + ", height " + std::to_string(p->ver.height) + ")");
    return v;
}

// ---------------------------------------------------------------- headers
bool LightClient::load_headers() {
    headers_.assign(1, p_.genesis.header);
    hashes_.assign(1, p_.genesis_hash);
    FILE* f = fopen((dir_ + "/headers.dat").c_str(), "rb");
    if (!f) return true;
    uint8_t buf[BlockHeader::SIZE];
    bool first = true;
    while (fread(buf, 1, sizeof buf, f) == sizeof buf) {
        Reader r(buf, sizeof buf);
        BlockHeader h = BlockHeader::read(r);
        if (first) { first = false; if (h.hash() != p_.genesis_hash) break; continue; }
        if (h.prev != hashes_.back()) break;
        headers_.push_back(h);
        hashes_.push_back(h.hash());
    }
    fclose(f);
    return true;
}

static void save_headers(const std::string& path, const std::vector<BlockHeader>& hs) {
    FILE* f = fopen((path + ".tmp").c_str(), "wb");
    if (!f) return;
    for (auto& h : hs) { uint8_t b[BlockHeader::SIZE]; h.serialize(b); fwrite(b, 1, sizeof b, f); }
    fclose(f);
    std::error_code ec;
    fs::rename(path + ".tmp", path, ec);
}

bool LightClient::append_header(const BlockHeader& h, std::string* why) {
    auto fail = [&](const char* r) { if (why) *why = r; return false; };
    if (h.prev != hashes_.back()) return fail("does not connect");
    Hash256 hash = h.hash();
    if (!check_pow(hash, h.bits, p_)) return fail("bad proof of work");
    int64_t tip = height();
    uint32_t want = next_bits(tip, [&](int i) { auto& x = headers_[size_t(tip - i)]; return HeaderInfo{x.time, x.bits}; }, p_);
    if (h.bits != want) return fail("wrong difficulty");
    std::vector<int64_t> t;
    for (int64_t i = tip; i >= 0 && i > tip - MEDIAN_TIME_SPAN; i--) t.push_back(int64_t(headers_[size_t(i)].time));
    std::sort(t.begin(), t.end());
    if (int64_t(h.time) <= t[t.size() / 2]) return fail("timestamp too old");
    if (int64_t(h.time) > now_seconds() + MAX_FUTURE_DRIFT) return fail("timestamp in the future");
    headers_.push_back(h);
    hashes_.push_back(hash);
    return true;
}

std::vector<Hash256> LightClient::locator() const {
    std::vector<Hash256> v;
    int64_t step = 1;
    for (int64_t h = height(); h >= 0; h -= step) {
        v.push_back(hashes_[size_t(h)]);
        if (v.size() > 10) step *= 2;
    }
    if (v.back() != p_.genesis_hash) v.push_back(p_.genesis_hash);
    return v;
}

static U256 header_work(const BlockHeader& h) { return work_from_target(U256::from_compact(h.bits)); }

bool LightClient::sync_headers(std::string* err) {
    if (peers_.empty()) { if (err) *err = "not connected"; return false; }
    // Ask the peer claiming the most blocks.
    auto best = std::max_element(peers_.begin(), peers_.end(), [](auto& a, auto& b) { return a->ver.height < b->ver.height; });
    Peer& p = **best;
    int64_t start = height();
    for (int round = 0; round < 100000; round++) {
        Writer w;
        auto loc = locator();
        w.varint(loc.size());
        for (auto& h : loc) w.hash(h);
        w.hash(Hash256{});
        Bytes reply;
        if (!exchange(p, Cmd::GetHeaders, w.buf, Cmd::Headers, reply, 30000)) { if (err) *err = "peer stopped answering"; return false; }
        Reader r(reply);
        size_t n = r.varint_max(MAX_HEADERS_PER_MSG);
        std::vector<BlockHeader> hs;
        for (size_t i = 0; i < n; i++) hs.push_back(BlockHeader::read(r));
        if (hs.empty()) break;
        // Fork handling: the batch may attach below our tip.
        if (hs[0].prev != hashes_.back()) {
            auto it = std::find(hashes_.begin(), hashes_.end(), hs[0].prev);
            if (it == hashes_.end()) { if (err) *err = "peer sent unconnected headers"; return false; }
            size_t fork = size_t(it - hashes_.begin());
            U256 ours, theirs;
            for (size_t i = fork + 1; i < headers_.size(); i++) ours += header_work(headers_[i]);
            for (auto& h : hs) theirs += header_work(h);
            if (theirs <= ours) break;
            if (headers_.size() - fork - 1 > size_t(MAX_REORG_DEPTH)) { if (err) *err = "refusing deep reorg"; return false; }
            headers_.resize(fork + 1);
            hashes_.resize(fork + 1);
        }
        for (auto& h : hs) {
            std::string why;
            if (!append_header(h, &why)) { if (err) *err = "invalid header from " + p.addr.str() + ": " + why; save_headers(dir_ + "/headers.dat", headers_); return false; }
        }
        if (on_status && hs.size() == MAX_HEADERS_PER_MSG) on_status("headers: " + std::to_string(height()));
        if (hs.size() < MAX_HEADERS_PER_MSG) break;
    }
    if (height() != start || true) save_headers(dir_ + "/headers.dat", headers_);
    return true;
}

// ---------------------------------------------------------------- networking
bool LightClient::send_msg(Peer& p, Cmd c, const Bytes& payload) {
    Bytes f = frame_message(p_, c, payload);
    size_t off = 0;
    while (off < f.size()) {
        int n = int(::send(p.s, (const char*)f.data() + off, int(f.size() - off), 0));
        if (n > 0) { off += size_t(n); continue; }
        if (n < 0 && sock_would_block(sock_error())) {
            pollfd_t pf{}; pf.fd = p.s; pf.events = POLLOUT;
            if (sock_poll(&pf, 1, 5000) <= 0) return false;
            continue;
        }
        return false;
    }
    return true;
}

bool LightClient::recv_msg(Peer& p, Cmd& c, Bytes& payload, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        std::string err;
        int r = p.rx.next(c, payload, &err);
        if (r > 0) return true;
        if (r < 0) return false;
        int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        if (left <= 0) return false;
        pollfd_t pf{}; pf.fd = p.s; pf.events = POLLIN;
        if (sock_poll(&pf, 1, std::min(left, 500)) <= 0) continue;
        uint8_t buf[65536];
        int n = int(::recv(p.s, (char*)buf, sizeof buf, 0));
        if (n <= 0) { if (n < 0 && sock_would_block(sock_error())) continue; return false; }
        p.rx.feed(buf, size_t(n));
    }
}

bool LightClient::exchange(Peer& p, Cmd send_cmd, const Bytes& payload, Cmd want, Bytes& reply, int timeout_ms) {
    if (!send_msg(p, send_cmd, payload)) return false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        if (left <= 0) return false;
        Cmd c;
        Bytes pl;
        if (!recv_msg(p, c, pl, left)) return false;
        if (c == want) { reply = std::move(pl); return true; }
        if (c == Cmd::Ping) send_msg(p, Cmd::Pong, pl);
        // everything else (inv, addr, header announcements) is ignored by the light client
    }
}

bool LightClient::handshake(Peer& p, int timeout_ms) {
    VersionMsg v;
    v.services = 0;
    v.nonce = nonce_;
    v.height = height();
    v.listen_port = 0;
    v.agent = "quant-termux:0.1.0";
    v.genesis = p_.genesis_hash;
    v.your_addr = p.addr;
    if (!send_msg(p, Cmd::Version, v.encode())) return false;
    bool got_ver = false, got_ack = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (!(got_ver && got_ack)) {
        int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        if (left <= 0) return false;
        Cmd c;
        Bytes pl;
        if (!recv_msg(p, c, pl, left)) return false;
        if (c == Cmd::Version) {
            Reader r(pl);
            p.ver = VersionMsg::decode(r);
            if (p.ver.genesis != p_.genesis_hash || !(p.ver.services & SERVICE_LIGHT_SERVE)) return false;
            got_ver = true;
            send_msg(p, Cmd::Verack, {});
        } else if (c == Cmd::Verack) {
            got_ack = true;
        }
    }
    return true;
}

std::vector<NetAddr> LightClient::discover(int timeout_s, size_t enough) {
    std::set<NetAddr> found;
    {
        std::ifstream f(dir_ + "/peers.txt");
        std::string line;
        while (std::getline(f, line)) { NetAddr a; if (NetAddr::parse(line, p_.p2p_port, a)) found.insert(a); }
    }
    // LAN: ask nodes on the same Wi-Fi to identify themselves.
    sock_t lan = udp_bind(0, true, nullptr);
    if (lan != BAD_SOCK) {
        Bytes q = {'Q', 'N', 'T', 'Q'};
        q.insert(q.end(), p_.magic, p_.magic + 4);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        sa.sin_port = htons(p_.lan_port);
        sendto(lan, (const char*)q.data(), int(q.size()), 0, (sockaddr*)&sa, sizeof sa);
    }
    std::vector<std::unique_ptr<Dht>> dhts;
    if (found.size() < enough) {
        for (bool v6 : {false, true}) {
            if (v6 && !net_ipv6_available()) continue;
            auto d = std::make_unique<Dht>(p_.dht_infohash, 0, 0, dir_ + (v6 ? "/dht6.dat" : "/dht4.dat"), v6);
            d->announce = false;
            if (!d->start(nullptr)) continue;
            d->on_peer = [&](const NetAddr& a) { found.insert(a); };
            dhts.push_back(std::move(d));
        }
        if (on_status) on_status("searching the BitTorrent DHT for Quant nodes...");
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s);
    size_t lan_found = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        std::vector<pollfd_t> fds;
        if (lan != BAD_SOCK) { pollfd_t f{}; f.fd = lan; f.events = POLLIN; fds.push_back(f); }
        for (auto& d : dhts) { pollfd_t f{}; f.fd = d->fd(); f.events = POLLIN; fds.push_back(f); }
        if (fds.empty()) break;
        sock_poll(fds.data(), fds.size(), 100);
        if (lan != BAD_SOCK) {
            uint8_t buf[64];
            sockaddr_storage from{};
            socklen_t fl = sizeof from;
            int n = int(recvfrom(lan, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &fl));
            if (n == 20 && std::memcmp(buf, "QNTL", 4) == 0 && std::memcmp(buf + 4, p_.magic, 4) == 0) {
                Reader r(buf + 8, 12);
                NetAddr a = NetAddr::from_sockaddr((sockaddr*)&from).with_port(uint16_t(r.u32le()));
                if (found.insert(a).second) { lan_found++; if (on_status) on_status("found node on local network: " + a.str()); }
            }
        }
        for (auto& d : dhts) { d->on_readable(); d->tick(now_millis()); }
        bool lan_window_over = std::chrono::steady_clock::now() > deadline - std::chrono::seconds(std::max(timeout_s - 2, 0));
        if (found.size() >= enough && lan_window_over) break;
        (void)lan_found;
    }
    for (auto& d : dhts) d->save();
    sock_close(lan);
    return std::vector<NetAddr>(found.begin(), found.end());
}

int LightClient::connect(const std::vector<std::string>& addnodes, int want, int timeout_s) {
    std::vector<NetAddr> cands;
    for (auto& s : addnodes) { NetAddr a; if (NetAddr::parse(s, p_.p2p_port, a)) cands.push_back(a); }
    if (int(cands.size()) < want) {
        auto more = discover(timeout_s, size_t(want) * 2);
        for (auto& a : more) if (std::find(cands.begin(), cands.end(), a) == cands.end()) cands.push_back(a);
    }
    std::vector<std::string> good;
    for (auto& a : cands) {
        if (int(peers_.size()) >= want) break;
        if (on_status) on_status("connecting to " + a.str() + " ...");
        auto p = std::make_unique<Peer>(p_);
        p->addr = a;
        p->s = tcp_connect_nb(a);
        if (p->s == BAD_SOCK) continue;
        pollfd_t pf{}; pf.fd = p->s; pf.events = POLLOUT;
        if (sock_poll(&pf, 1, 5000) <= 0) continue;
        int e = 0; socklen_t el = sizeof e;
        getsockopt(p->s, SOL_SOCKET, SO_ERROR, (char*)&e, &el);
        if (e || (pf.revents & (POLLERR | POLLHUP))) continue;
        if (!handshake(*p, 8000)) continue;
        if (p->ver.nonce == nonce_) continue;
        good.push_back(a.str());
        peers_.push_back(std::move(p));
    }
    // Remember working peers for next time (fast reconnect, no DHT needed).
    std::set<std::string> save(good.begin(), good.end());
    { std::ifstream f(dir_ + "/peers.txt"); std::string l; while (std::getline(f, l) && save.size() < 50) save.insert(l); }
    std::ofstream f(dir_ + "/peers.txt");
    for (auto& s : save) f << s << "\n";
    return int(peers_.size());
}

// ---------------------------------------------------------------- wallet
bool LightClient::refresh_wallet(Wallet& w, std::string* err) {
    if (peers_.empty()) { if (err) *err = "not connected"; return false; }
    std::map<Hash256, int64_t> height_of;
    for (int64_t h = 0; h <= height(); h++) height_of[hashes_[size_t(h)]] = h;
    for (int round = 0; round < 8; round++) {
        auto addrs = w.watched_addresses();
        std::map<OutPoint, WalletCoin> coins;
        std::set<OutPoint> pending_spent;
        std::map<Hash256, std::pair<int64_t, Amount>> received; // txid -> (height, amount)
        std::set<Hash256> coinbase_tx;
        int answered = 0;
        for (auto& pp : peers_) {
            for (size_t off = 0; off < addrs.size(); off += 200) {
                Writer q;
                size_t n = std::min<size_t>(200, addrs.size() - off);
                q.varint(n);
                for (size_t i = 0; i < n; i++) q.hash(addrs[off + i]);
                Bytes reply;
                if (!exchange(*pp, Cmd::GetUtxos, q.buf, Cmd::Utxos, reply, 20000)) break;
                answered++;
                try {
                    Reader r(reply);
                    r.u64le();
                    r.hash();
                    size_t np = r.varint_max(100000);
                    for (size_t i = 0; i < np; i++) {
                        UtxoProof u = UtxoProof::read(r);
                        // Verify: block is in our PoW-checked chain at the claimed height, the tx is in
                        // that block (Merkle proof), and the output really pays this amount/address.
                        auto hi = height_of.find(u.block);
                        if (hi == height_of.end() || hi->second != int64_t(u.coin.height)) continue;
                        Hash256 txid = blake3_tagged(ctx::TXID, u.tx_core);
                        if (txid != u.op.txid) continue;
                        if (!merkle_verify(txid, u.tx_index, u.tx_count, u.merkle, headers_[size_t(hi->second)].merkle_root)) continue;
                        Reader tr(u.tx_core);
                        Transaction tx = Transaction::read_core(tr);
                        if (u.op.n >= tx.outs.size()) continue;
                        const TxOut& o = tx.outs[u.op.n];
                        if (o.value != u.coin.out.value || o.addr != u.coin.out.addr || !w.is_mine(o.addr)) continue;
                        if (tx.is_coinbase() != u.coin.coinbase) continue;
                        if (!coins.count(u.op)) {
                            coins[u.op] = WalletCoin{u.op, o, hi->second, tx.is_coinbase(), false};
                            auto& rec = received[txid];
                            rec.first = hi->second;
                            rec.second += o.value;
                            if (tx.is_coinbase()) coinbase_tx.insert(txid);
                        }
                    }
                    size_t ns = r.varint_max(100000);
                    for (size_t i = 0; i < ns; i++) { OutPoint o; o.txid = r.hash(); o.n = uint32_t(r.varint()); pending_spent.insert(o); }
                    size_t nu = r.varint_max(100000);
                    for (size_t i = 0; i < nu; i++) {
                        OutPoint o; o.txid = r.hash(); o.n = uint32_t(r.varint());
                        TxOut out; out.value = r.varint(); out.addr_ver = r.u8(); out.addr = r.hash();
                        if (w.is_mine(out.addr) && !coins.count(o)) coins[o] = WalletCoin{o, out, -1, false, false};
                    }
                } catch (const std::exception&) {
                    continue;
                }
            }
        }
        if (!answered) { if (err) *err = "no peer answered"; return false; }
        std::vector<WalletCoin> v;
        for (auto& [o, c] : coins) { WalletCoin cc = c; cc.locked = pending_spent.count(o) != 0; v.push_back(cc); }
        size_t before = w.watched_addresses().size();
        w.replace_coins(v);
        // Record incoming payments in the history (sends are recorded when we broadcast them).
        auto hist = w.history();
        std::map<Hash256, WalletTx> by_id;
        for (auto& t : hist) by_id[t.txid] = t;
        for (auto& [txid, rec] : received) {
            auto it = by_id.find(txid);
            if (it == by_id.end()) {
                WalletTx t;
                t.txid = txid;
                t.height = rec.first;
                t.time = int64_t(headers_[size_t(rec.first)].time);
                t.delta = int64_t(rec.second);
                t.coinbase = coinbase_tx.count(txid) != 0;
                w.record_tx(t);
            } else if (it->second.height < 0) {
                WalletTx t = it->second; // our own send confirmed (its change came back)
                t.height = rec.first;
                w.record_tx(t);
            }
        }
        if (w.watched_addresses().size() == before) break; // lookahead stable
    }
    w.synced_height = height();
    w.synced_tip = hashes_.back();
    w.save();
    return true;
}

bool LightClient::broadcast(const Transaction& tx, std::string* err) {
    if (peers_.empty()) { if (err) *err = "not connected"; return false; }
    Bytes full = tx.full_bytes();
    int sent = 0;
    for (auto& p : peers_) if (send_msg(*p, Cmd::TxMsg, full)) sent++;
    if (!sent) { if (err) *err = "could not send to any peer"; return false; }
    Hash256 id = tx.txid();
    // Nodes only answer on rejection; give them a moment.
    for (auto& p : peers_) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
        while (std::chrono::steady_clock::now() < deadline) {
            Cmd c;
            Bytes pl;
            int left = int(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
            if (!recv_msg(*p, c, pl, std::max(left, 1))) break;
            if (c == Cmd::Reject) {
                Reader r(pl);
                r.u8();
                if (r.hash() == id) { if (err) *err = r.str(500); return false; }
            }
            if (c == Cmd::Ping) send_msg(*p, Cmd::Pong, pl);
        }
    }
    return true;
}

} // namespace quant
