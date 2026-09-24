#include "net/p2p.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <random>
#include <sstream>

#include "consensus/limits.h"
#include "crypto/random.h"
#include "util/log.h"

namespace quant {

static constexpr int MAX_INFLIGHT_PER_PEER = 16;
static constexpr int DOWNLOAD_WINDOW = 1024;
static constexpr size_t MAX_KNOWN_INV = 5000;

struct P2P::Peer {
    uint64_t id = 0;
    sock_t s = BAD_SOCK;
    NetAddr addr;
    bool inbound = false, manual = false;
    bool connecting = false;
    bool got_version = false, got_verack = false, sent_version = false;
    bool disconnect = false;
    VersionMsg ver;
    FrameReader rx;
    Bytes txbuf;
    size_t tx_off = 0;
    int64_t start_ms = 0, last_recv_ms = 0, ping_sent_ms = 0, last_getheaders_ms = 0;
    uint64_t ping_nonce = 0;
    double ping_ms = -1;
    int64_t best_height = 0;
    uint64_t bin = 0, bout = 0;
    int stalls = 0;
    std::set<Hash256> known;
    std::deque<Hash256> known_order;

    explicit Peer(const ChainParams& p) : rx(p) {}
    bool active() const { return got_version && got_verack && !disconnect; }
    bool full() const { return (ver.services & SERVICE_FULL) != 0; }
    void mark_known(const Hash256& h) {
        if (!known.insert(h).second) return;
        known_order.push_back(h);
        if (known_order.size() > MAX_KNOWN_INV) { known.erase(known_order.front()); known_order.pop_front(); }
    }
};

P2P::P2P(Chainstate& cs, Mempool& mp, P2POptions opt)
    : cs_(cs), mp_(mp), opt_(std::move(opt)), p_(cs.params()) {
    if (opt_.port == 0) opt_.port = p_.p2p_port;
    nonce_ = random_u64();
    cs_.on_tip.push_back([this](const BlockIndex*) { std::lock_guard l(q_mu_); q_tip_ = true; });
    mp_.on_added.push_back([this](const Transaction& tx) { std::lock_guard l(q_mu_); q_relay_.push_back(tx.txid()); });
}

P2P::~P2P() { stop(); }

bool P2P::start(std::string* err) {
    net_init();
    load_addrs();
    for (auto& a : opt_.addnodes) q_addnode_.push_back(a);
    if (opt_.listen) {
        std::string e;
        listen_ = tcp_listen(opt_.port, true, &e);
        if (listen_ == BAD_SOCK) { if (err) *err = e; return false; }
    }
    if (opt_.dht && !opt_.connect_only) {
        // Two DHTs: the IPv4 one and the IPv6 one (BEP 32). On IPv4-CGNAT connections such as
        // Starlink or mobile data, the IPv6 DHT is how other nodes find a reachable address for us.
        for (bool v6 : {false, true}) {
            if (v6 && !net_ipv6_available()) continue;
            auto d = std::make_unique<Dht>(p_.dht_infohash, opt_.port, opt_.port, opt_.datadir + (v6 ? "/dht6.dat" : "/dht4.dat"), v6);
            std::string e;
            if (!d->start(&e)) { logf("DHT (%s) disabled: %s", v6 ? "IPv6" : "IPv4", e.c_str()); continue; }
            d->on_peer = [this](const NetAddr& a) { add_addr(a); };
            d->on_my_ip = [this](const NetAddr& a) { learned_external(a.with_port(opt_.port)); };
            dhts_.push_back(std::move(d));
        }
    }
    if (opt_.lan && !opt_.connect_only) {
        std::string e;
        lan_ = udp_bind(p_.lan_port, true, &e);
        if (lan_ == BAD_SOCK) logf("LAN discovery disabled: %s", e.c_str());
    }
    if (opt_.upnp && opt_.listen && !opt_.connect_only) {
        upnp_ = std::make_unique<PortMapper>(opt_.port);
        upnp_->start();
    }
    running_ = true;
    th_ = std::thread([this] { loop(); });
    logf("P2P listening on port %u (%s network)", opt_.port, p_.name.c_str());
    return true;
}

void P2P::stop() {
    if (!running_) return;
    running_ = false;
    if (th_.joinable()) th_.join();
    for (auto& p : peers_) sock_close(p->s);
    peers_.clear();
    sock_close(listen_);
    sock_close(lan_);
    listen_ = lan_ = BAD_SOCK;
    for (auto& d : dhts_) d->save();
    dhts_.clear();
    upnp_.reset();
    save_addrs();
}

// ---------------------------------------------------------------- public (thread-safe)
void P2P::broadcast_tx(const Transaction& tx) { std::lock_guard l(q_mu_); q_relay_.push_back(tx.txid()); }
void P2P::add_node(const std::string& hp) { std::lock_guard l(q_mu_); q_addnode_.push_back(hp); }
void P2P::disconnect(uint64_t id) { std::lock_guard l(q_mu_); q_disconnect_.push_back(id); }
std::vector<PeerInfo> P2P::peers() const { std::lock_guard l(info_mu_); return info_; }
NetStats P2P::stats() const { std::lock_guard l(info_mu_); return stats_; }

// ---------------------------------------------------------------- address book
void P2P::add_addr(const NetAddr& a, bool manual) {
    if (a.port == 0 || a.is_zero()) return;
    if (a == external4_ || a == external6_) return;
    auto& info = addrs_[a];
    if (manual) info.manual = true;
    if (addrs_.size() > 5000) {
        // forget the worst entry
        auto worst = std::max_element(addrs_.begin(), addrs_.end(), [](auto& x, auto& y) { return x.second.attempts < y.second.attempts; });
        if (!worst->second.manual) addrs_.erase(worst);
    }
}

void P2P::load_addrs() {
    std::ifstream f(opt_.datadir + "/peers.txt");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream is(line);
        std::string hp;
        int64_t ok = 0;
        is >> hp >> ok;
        NetAddr a;
        if (NetAddr::parse(hp, p_.p2p_port, a)) { add_addr(a); addrs_[a].last_ok = ok; }
    }
    if (!addrs_.empty()) logf("loaded %zu saved peer addresses", addrs_.size());
}

void P2P::save_addrs() {
    std::ofstream f(opt_.datadir + "/peers.txt");
    std::vector<std::pair<NetAddr, AddrInfo>> v(addrs_.begin(), addrs_.end());
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second.last_ok > b.second.last_ok; });
    int n = 0;
    for (auto& [a, i] : v) {
        if (i.attempts > 10 && i.last_ok == 0) continue;
        f << a.str() << " " << i.last_ok << "\n";
        if (++n >= 2000) break;
    }
}

void P2P::learned_external(const NetAddr& a) {
    if (!a.routable()) return;
    int& v = external_votes_[a];
    v++;
    NetAddr& ext = a.is_v4() ? external4_ : external6_;
    if (v >= 2 && !(ext == a)) {
        ext = a;
        addrs_.erase(a);
        logf("our public address appears to be %s", a.str().c_str());
    }
}

// ---------------------------------------------------------------- connections
void P2P::connect_to(const NetAddr& a, bool manual) {
    for (auto& p : peers_) if (p->addr == a && !p->inbound) return;
    auto ban = banned_.find(a.ip);
    if (ban != banned_.end() && ban->second > now_seconds() && !manual) return;
    if (!a.is_v4() && !net_ipv6_available()) return;
    sock_t s = tcp_connect_nb(a);
    auto& info = addrs_[a];
    info.last_try = now_seconds();
    info.attempts++;
    if (manual) info.manual = true;
    if (s == BAD_SOCK) return;
    auto p = std::make_unique<Peer>(p_);
    p->id = next_peer_id_++;
    p->s = s;
    p->addr = a;
    p->manual = manual;
    p->connecting = true;
    p->start_ms = now_millis();
    peers_.push_back(std::move(p));
}

void P2P::accept_inbound() {
    for (int i = 0; i < 16; i++) {
        sockaddr_storage sa{};
        socklen_t len = sizeof sa;
        sock_t s = ::accept(listen_, (sockaddr*)&sa, &len);
        if (s == BAD_SOCK) return;
        NetAddr a = NetAddr::from_sockaddr((sockaddr*)&sa);
        int inbound = 0;
        for (auto& p : peers_) inbound += p->inbound;
        auto ban = banned_.find(a.ip);
        if (inbound >= opt_.max_inbound || (ban != banned_.end() && ban->second > now_seconds())) { sock_close(s); continue; }
        sock_nonblocking(s);
        auto p = std::make_unique<Peer>(p_);
        p->id = next_peer_id_++;
        p->s = s;
        p->addr = a;
        p->inbound = true;
        p->start_ms = p->last_recv_ms = now_millis();
        peers_.push_back(std::move(p));
    }
}

void P2P::on_connected(Peer& p) {
    p.connecting = false;
    p.last_recv_ms = now_millis();
    VersionMsg v;
    v.services = SERVICE_FULL | SERVICE_LIGHT_SERVE;
    v.nonce = nonce_;
    { std::lock_guard l(cs_.mu); v.height = cs_.height(); }
    v.listen_port = opt_.listen ? opt_.port : 0;
    v.agent = opt_.agent;
    v.genesis = p_.genesis_hash;
    v.your_addr = p.addr;
    send(p, Cmd::Version, v.encode());
    p.sent_version = true;
}

void P2P::send(Peer& p, Cmd c, const Bytes& payload) {
    if (p.disconnect || p.s == BAD_SOCK) return;
    Bytes f = frame_message(p_, c, payload);
    if (p.tx_off > 0 && p.tx_off == p.txbuf.size()) { p.txbuf.clear(); p.tx_off = 0; }
    p.txbuf.insert(p.txbuf.end(), f.begin(), f.end());
    if (p.txbuf.size() - p.tx_off > 64 * 1024 * 1024) { p.disconnect = true; return; }
    flush_peer(p);
}

void P2P::flush_peer(Peer& p) {
    while (p.tx_off < p.txbuf.size()) {
        size_t want = std::min<size_t>(p.txbuf.size() - p.tx_off, 1 << 20);
        int n = int(::send(p.s, (const char*)p.txbuf.data() + p.tx_off, int(want), 0));
        if (n > 0) { p.tx_off += size_t(n); p.bout += uint64_t(n); bytes_out_ += uint64_t(n); continue; }
        if (n < 0 && sock_would_block(sock_error())) break;
        p.disconnect = true;
        break;
    }
    if (p.tx_off == p.txbuf.size()) { p.txbuf.clear(); p.tx_off = 0; }
}

void P2P::read_peer(Peer& p) {
    uint8_t buf[65536];
    for (int k = 0; k < 64; k++) {
        int n = int(::recv(p.s, (char*)buf, sizeof buf, 0));
        if (n > 0) {
            p.rx.feed(buf, size_t(n));
            p.bin += uint64_t(n);
            bytes_in_ += uint64_t(n);
            p.last_recv_ms = now_millis();
            if (p.rx.buffered() > 2 * MAX_MESSAGE) { misbehave(p, "flood", false); return; }
            continue;
        }
        if (n < 0 && sock_would_block(sock_error())) break;
        p.disconnect = true;
        break;
    }
    Cmd c;
    Bytes payload;
    std::string err;
    for (;;) {
        int r = p.rx.next(c, payload, &err);
        if (r == 0) break;
        if (r < 0) { misbehave(p, err, false); return; }
        try {
            handle(p, c, payload);
        } catch (const std::exception& e) {
            misbehave(p, std::string("malformed ") + cmd_name(c) + ": " + e.what());
        }
        if (p.disconnect) return;
    }
}

void P2P::misbehave(Peer& p, const std::string& why, bool ban) {
    logf("peer %s: %s - disconnecting", p.addr.str().c_str(), why.c_str());
    p.disconnect = true;
    if (ban && !p.manual) banned_[p.addr.ip] = now_seconds() + 3600;
}

void P2P::send_getheaders(Peer& p, bool from_best_header) {
    Writer w;
    std::vector<Hash256> loc;
    {
        std::lock_guard l(cs_.mu);
        loc = cs_.locator(from_best_header ? cs_.best_header() : nullptr);
    }
    w.varint(loc.size());
    for (auto& h : loc) w.hash(h);
    w.hash(Hash256{});
    send(p, Cmd::GetHeaders, w.buf);
    p.last_getheaders_ms = now_millis();
}

// ---------------------------------------------------------------- message handling
void P2P::handle(Peer& p, Cmd c, const Bytes& payload) {
    Reader r(payload);
    if (!p.got_version && c != Cmd::Version) { misbehave(p, "message before version", false); return; }

    switch (c) {
    case Cmd::Version: {
        if (p.got_version) { misbehave(p, "duplicate version", false); return; }
        p.ver = VersionMsg::decode(r);
        if (p.ver.genesis != p_.genesis_hash) { misbehave(p, "different network (genesis mismatch)", false); return; }
        if (p.ver.nonce == nonce_) {
            // Connected to ourselves: remember that address so we never try it again.
            if (!p.inbound) self_addrs_.insert(p.addr);
            addrs_.erase(p.addr);
            p.disconnect = true;
            return;
        }
        for (auto& other : peers_)
            if (other.get() != &p && other->got_version && other->ver.nonce == p.ver.nonce) {
                p.disconnect = true; // already connected to this node the other way round
                return;
            }
        p.got_version = true;
        p.best_height = p.ver.height;
        if (p.inbound) {
            if (p.ver.listen_port) add_addr(p.addr.with_port(p.ver.listen_port));
            on_connected(p);
        }
        learned_external(p.ver.your_addr.with_port(opt_.port));
        send(p, Cmd::Verack, {});
        break;
    }
    case Cmd::Verack: {
        p.got_verack = true;
        if (!p.inbound) {
            auto& info = addrs_[p.addr];
            info.last_ok = now_seconds();
            info.attempts = 0;
        }
        logf("connected to %s peer %s (%s, height %lld)", p.inbound ? "inbound" : "outbound", p.addr.str().c_str(),
             p.ver.agent.c_str(), (long long)p.ver.height);
        if (p.full()) {
            if (!p.inbound) send(p, Cmd::GetAddr, {});
            send_getheaders(p, true);
        }
        // Tell the peer about our own address when we're reachable.
        // Tell the peer our own addresses. IPv6 is usually directly reachable (no NAT), so we
        // always advertise it; IPv4 only when we know inbound works (UPnP or seen inbound peers).
        bool reach4 = (upnp_ && upnp_->mapped()) ||
                      std::any_of(peers_.begin(), peers_.end(), [](auto& x) { return x->inbound && x->addr.is_v4() && x->addr.routable(); });
        std::vector<NetAddr> mine;
        if (reach4 && external4_.routable()) mine.push_back(external4_);
        if (opt_.listen && external6_.routable()) mine.push_back(external6_);
        if (!mine.empty()) {
            Writer w;
            w.varint(mine.size());
            for (auto& a : mine) { write_addr(w, a); w.u64le(uint64_t(now_seconds())); }
            send(p, Cmd::Addr, w.buf);
        }
        break;
    }
    case Cmd::Ping: send(p, Cmd::Pong, payload); break;
    case Cmd::Pong: {
        uint64_t n = r.u64le();
        if (n == p.ping_nonce && p.ping_sent_ms) p.ping_ms = double(now_millis() - p.ping_sent_ms);
        break;
    }
    case Cmd::GetAddr: {
        std::vector<NetAddr> v;
        for (auto& [a, i] : addrs_)
            if (i.last_ok && (a.routable() || p.addr.is_local())) v.push_back(a);
        std::shuffle(v.begin(), v.end(), std::mt19937_64(random_u64()));
        if (v.size() > 500) v.resize(500);
        Writer w;
        w.varint(v.size());
        for (auto& a : v) { write_addr(w, a); w.u64le(uint64_t(addrs_[a].last_ok)); }
        send(p, Cmd::Addr, w.buf);
        break;
    }
    case Cmd::Addr: {
        size_t n = r.varint_max(1000);
        for (size_t i = 0; i < n; i++) {
            NetAddr a = read_addr(r);
            r.u64le();
            if (a.routable() || (a.is_local() && p.addr.is_local())) add_addr(a);
        }
        break;
    }
    case Cmd::Inv: {
        size_t n = r.varint_max(50000);
        Writer want;
        size_t nwant = 0;
        Writer items;
        bool block_inv = false;
        for (size_t i = 0; i < n; i++) {
            uint8_t t = r.u8();
            Hash256 h = r.hash();
            p.mark_known(h);
            if (t == INV_TX) {
                std::lock_guard l(cs_.mu);
                if (!mp_.contains(h) && !cs_.find_tx_block(h)) { items.u8(INV_TX); items.hash(h); nwant++; }
            } else if (t == INV_BLOCK) {
                block_inv = true;
            }
        }
        if (nwant) { want.varint(nwant); want.raw(items.buf); send(p, Cmd::GetData, want.buf); }
        if (block_inv) send_getheaders(p, true);
        break;
    }
    case Cmd::GetData: {
        size_t n = r.varint_max(50000);
        Writer nf;
        size_t nnf = 0;
        for (size_t i = 0; i < n; i++) {
            uint8_t t = r.u8();
            Hash256 h = r.hash();
            if (t == INV_TX) {
                std::optional<Transaction> tx;
                { std::lock_guard l(cs_.mu); tx = mp_.get(h); }
                if (tx) send(p, Cmd::TxMsg, tx->full_bytes());
                else { nf.u8(t); nf.hash(h); nnf++; }
            } else if (t == INV_BLOCK) {
                Block b;
                bool gotw = false, ok = false;
                {
                    std::lock_guard l(cs_.mu);
                    BlockIndex* bi = cs_.lookup(h);
                    ok = bi && cs_.read_block(bi, b, true, &gotw);
                }
                if (ok) {
                    Writer w;
                    w.u8(gotw ? 1 : 0);
                    w.raw(gotw ? b.full_bytes() : b.core_bytes());
                    send(p, Cmd::BlockMsg, w.buf);
                } else { nf.u8(t); nf.hash(h); nnf++; }
            }
        }
        if (nnf) { Writer w; w.varint(nnf); w.raw(nf.buf); send(p, Cmd::NotFound, w.buf); }
        break;
    }
    case Cmd::NotFound: {
        size_t n = r.varint_max(50000);
        for (size_t i = 0; i < n; i++) {
            r.u8();
            Hash256 h = r.hash();
            auto it = inflight_.find(h);
            if (it != inflight_.end() && it->second.first == p.id) { inflight_.erase(it); no_witness_.insert({h, p.id}); }
        }
        break;
    }
    case Cmd::GetHeaders: {
        size_t n = r.varint_max(200);
        std::vector<Hash256> loc;
        for (size_t i = 0; i < n; i++) loc.push_back(r.hash());
        Hash256 stop = r.hash();
        Writer w;
        std::vector<BlockHeader> hs;
        {
            std::lock_guard l(cs_.mu);
            BlockIndex* f = cs_.find_fork_from_locator(loc);
            for (int64_t h = f ? f->height + 1 : 0; h <= cs_.height() && hs.size() < MAX_HEADERS_PER_MSG; h++) {
                BlockIndex* b = cs_.at_height(h);
                hs.push_back(b->header);
                if (b->hash == stop) break;
            }
        }
        w.varint(hs.size());
        for (auto& h : hs) h.write(w);
        send(p, Cmd::Headers, w.buf);
        break;
    }
    case Cmd::Headers: {
        size_t n = r.varint_max(MAX_HEADERS_PER_MSG);
        std::vector<BlockHeader> hs;
        for (size_t i = 0; i < n; i++) hs.push_back(BlockHeader::read(r));
        bool orphan = false;
        BlockIndex* last = nullptr;
        for (auto& h : hs) {
            std::string why;
            BlockIndex* bi = nullptr;
            auto res = cs_.accept_header(h, &why, &bi);
            if (res == Chainstate::HeaderResult::Orphan) { orphan = true; break; }
            if (res == Chainstate::HeaderResult::Invalid) {
                if (why == "time-too-new") break;
                misbehave(p, "invalid header: " + why);
                return;
            }
            last = bi;
            p.mark_known(bi->hash);
        }
        if (last) p.best_height = std::max(p.best_height, last->height);
        if (orphan) send_getheaders(p, true);
        else if (n == MAX_HEADERS_PER_MSG) send_getheaders(p, true);
        request_blocks(now_millis());
        break;
    }
    case Cmd::BlockMsg: {
        bool has_w = r.u8() != 0;
        Block b = Block::read_core(r);
        if (has_w) b.read_witness(r);
        Hash256 h = b.header.hash();
        p.mark_known(h);
        auto it = inflight_.find(h);
        if (it != inflight_.end()) inflight_.erase(it);
        std::string why;
        bool is_new = false;
        if (!cs_.accept_block(b, has_w, &why, &is_new)) {
            if (why == "witness-required") { no_witness_.insert({h, p.id}); break; }
            if (why == "orphan") { send_getheaders(p, true); break; }
            if (why == "time-too-new" || why == "disk-write-failed") break;
            misbehave(p, "invalid block: " + why);
            return;
        }
        request_blocks(now_millis());
        break;
    }
    case Cmd::TxMsg: {
        Transaction tx = Transaction::read_full(r);
        Hash256 id = tx.txid();
        p.mark_known(id);
        std::string why;
        if (!mp_.accept(tx, &why)) {
            if (why != "already-in-mempool" && why != "already-confirmed") {
                Writer w;
                w.u8(INV_TX); w.hash(id); w.str(why);
                send(p, Cmd::Reject, w.buf);
            }
        }
        break;
    }
    case Cmd::GetUtxos: send(p, Cmd::Utxos, build_utxo_reply(payload)); break;
    case Cmd::Utxos: case Cmd::Reject: break;
    }
}

Bytes P2P::build_utxo_reply(const Bytes& req) {
    Reader r(req);
    size_t n = r.varint_max(200);
    std::vector<Hash256> addrs;
    for (size_t i = 0; i < n; i++) addrs.push_back(r.hash());
    std::lock_guard l(cs_.mu);
    Writer w;
    w.u64le(uint64_t(cs_.height()));
    w.hash(cs_.tip()->hash);
    std::vector<UtxoProof> proofs;
    std::map<Hash256, std::pair<Block, std::vector<Hash256>>> cache;
    std::vector<OutPoint> spent_pending;
    for (auto& a : addrs) {
        for (auto& [op, coin] : cs_.coins_for_address(a)) {
            if (proofs.size() >= 1000) break;
            auto bh = cs_.find_tx_block(op.txid);
            if (!bh) continue;
            auto ci = cache.find(*bh);
            if (ci == cache.end()) {
                Block b;
                if (!cs_.read_block(cs_.lookup(*bh), b, false)) continue;
                std::vector<Hash256> ids;
                for (auto& t : b.txs) ids.push_back(t.txid());
                ci = cache.emplace(*bh, std::make_pair(std::move(b), std::move(ids))).first;
            }
            auto& ids = ci->second.second;
            size_t idx = size_t(std::find(ids.begin(), ids.end(), op.txid) - ids.begin());
            if (idx >= ids.size()) continue;
            UtxoProof u;
            u.op = op;
            u.coin = coin;
            u.block = *bh;
            u.tx_core = ci->second.first.txs[idx].core_bytes();
            u.tx_index = uint32_t(idx);
            u.tx_count = uint32_t(ids.size());
            u.merkle = merkle_proof(ids, idx);
            proofs.push_back(std::move(u));
            if (mp_.spends(op)) spent_pending.push_back(op);
        }
    }
    w.varint(proofs.size());
    for (auto& u : proofs) u.write(w);
    w.varint(spent_pending.size());
    for (auto& o : spent_pending) { w.hash(o.txid); w.varint(o.n); }
    // Unconfirmed outputs paying these addresses.
    std::set<Hash256> want(addrs.begin(), addrs.end());
    std::vector<std::pair<OutPoint, TxOut>> unconf;
    for (auto* e : mp_.all())
        for (uint32_t i = 0; i < e->tx.outs.size(); i++)
            if (want.count(e->tx.outs[i].addr) && !mp_.spends(OutPoint{e->txid, i}))
                unconf.push_back({OutPoint{e->txid, i}, e->tx.outs[i]});
    w.varint(unconf.size());
    for (auto& [o, out] : unconf) { w.hash(o.txid); w.varint(o.n); w.varint(out.value); w.u8(out.addr_ver); w.hash(out.addr); }
    return w.buf;
}

// ---------------------------------------------------------------- block download
void P2P::request_blocks(int64_t now) {
    std::map<uint64_t, std::vector<Hash256>> batches;
    {
        std::lock_guard l(cs_.mu);
        BlockIndex* best = cs_.best_header();
        BlockIndex* tip = cs_.tip();
        if (!best || best->chainwork <= tip->chainwork) return;
        BlockIndex* fork = cs_.ancestor(best, std::min(best->height, tip->height));
        while (fork && !cs_.in_active_chain(fork)) fork = fork->prev;
        if (!fork) return;
        std::map<uint64_t, int> load;
        for (auto& [h, v] : inflight_) load[v.first]++;
        int64_t end = std::min(best->height, fork->height + DOWNLOAD_WINDOW);
        for (int64_t h = fork->height + 1; h <= end; h++) {
            BlockIndex* b = cs_.ancestor(best, h);
            if (!b || b->have_data || inflight_.count(b->hash)) continue;
            Peer* pick = nullptr;
            for (auto& pp : peers_) {
                Peer* q = pp.get();
                if (!q->active() || !q->full() || q->best_height < h) continue;
                if (load[q->id] >= MAX_INFLIGHT_PER_PEER || no_witness_.count({b->hash, q->id})) continue;
                if (!pick || load[q->id] < load[pick->id]) pick = q;
            }
            if (!pick) continue;
            load[pick->id]++;
            inflight_[b->hash] = {pick->id, now};
            batches[pick->id].push_back(b->hash);
        }
    }
    for (auto& [id, hashes] : batches) {
        for (auto& pp : peers_) {
            if (pp->id != id) continue;
            Writer w;
            w.varint(hashes.size());
            for (auto& h : hashes) { w.u8(INV_BLOCK); w.hash(h); }
            send(*pp, Cmd::GetData, w.buf);
        }
    }
}

// ---------------------------------------------------------------- LAN discovery
void P2P::lan_tick(int64_t now) {
    if (lan_ == BAD_SOCK || now - last_lan_ < 20000) return;
    last_lan_ = now;
    Writer w;
    w.raw((const uint8_t*)"QNTL", 4);
    w.raw(p_.magic, 4);
    w.u32le(opt_.port);
    w.u64le(nonce_);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sa.sin_port = htons(p_.lan_port);
    sendto(lan_, (const char*)w.buf.data(), int(w.buf.size()), 0, (sockaddr*)&sa, sizeof sa);
}

void P2P::lan_read() {
    uint8_t buf[256];
    for (int k = 0; k < 32; k++) {
        sockaddr_storage from{};
        socklen_t fl = sizeof from;
        int n = int(recvfrom(lan_, (char*)buf, sizeof buf, 0, (sockaddr*)&from, &fl));
        if (n <= 0) return;
        if (n == 8 && std::memcmp(buf, "QNTQ", 4) == 0 && std::memcmp(buf + 4, p_.magic, 4) == 0) {
            // A light wallet on the LAN is asking for nodes: answer it directly.
            Writer w;
            w.raw((const uint8_t*)"QNTL", 4);
            w.raw(p_.magic, 4);
            w.u32le(opt_.port);
            w.u64le(nonce_);
            sendto(lan_, (const char*)w.buf.data(), int(w.buf.size()), 0, (sockaddr*)&from, fl);
            continue;
        }
        if (n != 20 || std::memcmp(buf, "QNTL", 4) != 0 || std::memcmp(buf + 4, p_.magic, 4) != 0) continue;
        Reader r(buf + 8, 12);
        uint16_t port = uint16_t(r.u32le());
        uint64_t nonce = r.u64le();
        if (nonce == nonce_) continue;
        NetAddr a = NetAddr::from_sockaddr((sockaddr*)&from).with_port(port);
        bool known = addrs_.count(a);
        add_addr(a);
        if (!known) {
            logf("LAN: found Quant node %s", a.str().c_str());
            connect_to(a, false);
        }
    }
}

// ---------------------------------------------------------------- periodic work
void P2P::process_queues() {
    std::deque<Transaction> txs;
    std::deque<Hash256> relay;
    std::deque<std::string> addn;
    std::deque<uint64_t> disc;
    bool tip;
    {
        std::lock_guard l(q_mu_);
        txs.swap(q_tx_);
        relay.swap(q_relay_);
        addn.swap(q_addnode_);
        disc.swap(q_disconnect_);
        tip = q_tip_;
        q_tip_ = false;
    }
    for (auto& s : addn) {
        NetAddr a;
        if (NetAddr::parse(s, p_.p2p_port, a)) { add_addr(a, true); connect_to(a, true); }
        else logf("addnode: cannot resolve %s", s.c_str());
    }
    for (auto id : disc) for (auto& p : peers_) if (p->id == id) p->disconnect = true;
    if (!relay.empty()) {
        for (auto& p : peers_) {
            if (!p->active()) continue;
            Writer items;
            size_t n = 0;
            for (auto& h : relay) {
                if (p->known.count(h)) continue;
                p->mark_known(h);
                items.u8(INV_TX); items.hash(h); n++;
            }
            if (n) { Writer w; w.varint(n); w.raw(items.buf); send(*p, Cmd::Inv, w.buf); }
        }
    }
    if (tip) {
        BlockHeader hdr;
        int64_t h;
        bool ibd;
        {
            std::lock_guard l(cs_.mu);
            hdr = cs_.tip()->header;
            h = cs_.height();
            ibd = cs_.is_initial_sync();
        }
        if (!ibd && h != last_announce_height_) {
            last_announce_height_ = h;
            Hash256 hh = hdr.hash();
            for (auto& p : peers_) {
                if (!p->active() || p->known.count(hh)) continue;
                p->mark_known(hh);
                Writer w;
                w.varint(1);
                hdr.write(w);
                send(*p, Cmd::Headers, w.buf);
            }
        }
    }
}

void P2P::maintain(int64_t now) {
    int outbound = 0;
    for (auto& p : peers_) {
        if (p->disconnect) continue;
        if (p->connecting && now - p->start_ms > 10000) { p->disconnect = true; continue; }
        if (!p->connecting && !p->active() && now - p->start_ms > 30000) { p->disconnect = true; continue; }
        if (!p->inbound) outbound++;
        if (p->active()) {
            if (now - p->last_recv_ms > 5 * 60000) { logf("peer %s timed out", p->addr.str().c_str()); p->disconnect = true; continue; }
            if (now - p->ping_sent_ms > 60000) {
                p->ping_nonce = random_u64();
                p->ping_sent_ms = now;
                Writer w; w.u64le(p->ping_nonce);
                send(*p, Cmd::Ping, w.buf);
            }
            int64_t our;
            { std::lock_guard l(cs_.mu); our = cs_.best_header()->height; }
            if (p->full() && p->best_height > our && now - p->last_getheaders_ms > 30000) send_getheaders(*p, true);
        }
    }
    // Stalled block requests.
    for (auto it = inflight_.begin(); it != inflight_.end();) {
        if (now - it->second.second > 60000) {
            for (auto& p : peers_) if (p->id == it->second.first && ++p->stalls > 5) p->disconnect = true;
            it = inflight_.erase(it);
        } else ++it;
    }
    // Keep manual nodes connected.
    for (auto& [a, info] : addrs_) {
        if (!info.manual) continue;
        bool connected = std::any_of(peers_.begin(), peers_.end(), [&](auto& p) { return p->addr == a && !p->disconnect; });
        if (!connected && now_seconds() - info.last_try > 15) connect_to(a, true);
    }
    // Fill outbound slots.
    if (!opt_.connect_only && outbound < opt_.max_outbound) {
        std::vector<NetAddr> cands;
        int64_t t = now_seconds();
        for (auto& [a, info] : addrs_) {
            if (a == external4_ || a == external6_ || self_addrs_.count(a)) continue;
            int64_t backoff = std::min<int64_t>(60LL << std::min(info.attempts, 6), 3600);
            if (info.last_try && t - info.last_try < backoff) continue;
            bool connected = std::any_of(peers_.begin(), peers_.end(), [&](auto& p) { return p->addr == a; });
            if (!connected) cands.push_back(a);
        }
        std::shuffle(cands.begin(), cands.end(), std::mt19937_64(random_u64()));
        std::stable_sort(cands.begin(), cands.end(), [&](auto& x, auto& y) { return addrs_[x].last_ok > addrs_[y].last_ok; });
        for (size_t i = 0; i < cands.size() && outbound < opt_.max_outbound && i < 4; i++, outbound++) connect_to(cands[i], false);
    }
    request_blocks(now);
    for (auto& d : dhts_) d->tick(now);
    lan_tick(now);
    if (now - last_save_ > 5 * 60000) { last_save_ = now; save_addrs(); for (auto& d : dhts_) d->save(); }
}

void P2P::publish_info() {
    std::vector<PeerInfo> v;
    NetStats s;
    int64_t now = now_millis();
    for (auto& p : peers_) {
        if (p->connecting || p->disconnect) continue;
        int inflight = 0;
        for (auto& [h, x] : inflight_) inflight += x.first == p->id;
        v.push_back(PeerInfo{p->id, p->addr.str(), p->inbound, !p->full(), p->ver.agent, p->best_height,
                             (now - p->start_ms) / 1000, p->ping_ms, p->bin, p->bout, inflight});
        if (p->active()) (p->inbound ? s.inbound : s.outbound)++;
    }
    s.bytes_in = bytes_in_;
    s.bytes_out = bytes_out_;
    s.known_addrs = addrs_.size();
    s.dht_status.clear();
    for (auto& d : dhts_) s.dht_status += (s.dht_status.empty() ? "" : "  |  ") + d->status();
    if (s.dht_status.empty()) s.dht_status = "off";
    s.upnp_status = upnp_ ? upnp_->status() : "off";
    s.lan_status = lan_ != BAD_SOCK ? "broadcasting on UDP " + std::to_string(p_.lan_port) : "off";
    s.external_addr = external4_.is_zero() ? "IPv4 unknown" : external4_.str();
    s.external_addr += external6_.is_zero() ? "  |  IPv6 unknown" : "  |  " + external6_.str();
    s.listening = listen_ != BAD_SOCK;
    peer_count_ = v.size();
    std::lock_guard l(info_mu_);
    info_ = std::move(v);
    stats_ = s;
}

void P2P::loop() {
    int64_t last_maint = 0;
    std::vector<pollfd_t> fds;
    std::vector<Peer*> fdpeer;
    while (running_) {
        fds.clear();
        fdpeer.clear();
        auto addfd = [&](sock_t s, short ev, Peer* p) {
            pollfd_t f{};
            f.fd = s;
            f.events = ev;
            fds.push_back(f);
            fdpeer.push_back(p);
        };
        if (listen_ != BAD_SOCK) addfd(listen_, POLLIN, nullptr);
        for (auto& d : dhts_) addfd(d->fd(), POLLIN, nullptr);
        if (lan_ != BAD_SOCK) addfd(lan_, POLLIN, nullptr);
        for (auto& p : peers_) {
            short ev = POLLIN;
            if (p->connecting || p->tx_off < p->txbuf.size()) ev |= POLLOUT;
            if (p->connecting) ev = POLLOUT;
            addfd(p->s, ev, p.get());
        }
        int r = fds.empty() ? 0 : sock_poll(fds.data(), fds.size(), 50);
        if (fds.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (r > 0) {
            for (size_t i = 0; i < fds.size(); i++) {
                short re = fds[i].revents;
                if (!re) continue;
                Peer* p = fdpeer[i];
                if (!p) {
                    if (fds[i].fd == listen_) accept_inbound();
                    else if (auto it = std::find_if(dhts_.begin(), dhts_.end(), [&](auto& d) { return d->fd() == fds[i].fd; }); it != dhts_.end()) (*it)->on_readable();
                    else if (fds[i].fd == lan_) lan_read();
                    continue;
                }
                if (p->connecting) {
                    if (re & (POLLOUT | POLLERR | POLLHUP)) {
                        int err = 0;
                        socklen_t el = sizeof err;
                        getsockopt(p->s, SOL_SOCKET, SO_ERROR, (char*)&err, &el);
                        if (err || (re & (POLLERR | POLLHUP))) p->disconnect = true;
                        else on_connected(*p);
                    }
                    continue;
                }
                if (re & (POLLIN | POLLHUP | POLLERR)) read_peer(*p);
                if (!p->disconnect && (re & POLLOUT)) flush_peer(*p);
            }
        }
        process_queues();
        int64_t now = now_millis();
        if (now - last_maint >= 500) {
            last_maint = now;
            maintain(now);
            publish_info();
        }
        // Reap.
        for (auto it = peers_.begin(); it != peers_.end();) {
            if ((*it)->disconnect) {
                Peer& p = **it;
                if (p.active()) logf("disconnected %s", p.addr.str().c_str());
                for (auto f = inflight_.begin(); f != inflight_.end();)
                    f = f->second.first == p.id ? inflight_.erase(f) : std::next(f);
                sock_close(p.s);
                it = peers_.erase(it);
            } else ++it;
        }
    }
}

} // namespace quant
