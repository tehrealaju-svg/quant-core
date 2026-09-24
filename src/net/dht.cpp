#include "net/dht.h"

#include <algorithm>

#include "crypto/hash.h"
#include "crypto/random.h"
#include "util/log.h"
#include "util/serialize.h"

namespace quant {

// ---------------------------------------------------------------- bencode
struct BVal {
    enum T { Int, Str, List, Dict } t = Str;
    int64_t i = 0;
    std::string s;
    std::vector<BVal> l;
    std::map<std::string, BVal> d;
    BVal() = default;
    BVal(int64_t v) : t(Int), i(v) {}
    BVal(std::string v) : t(Str), s(std::move(v)) {}
    static BVal dict() { BVal b; b.t = Dict; return b; }
    const BVal* get(const std::string& k) const {
        if (t != Dict) return nullptr;
        auto it = d.find(k);
        return it == d.end() ? nullptr : &it->second;
    }
    const std::string* str(const std::string& k) const {
        auto* v = get(k);
        return v && v->t == Str ? &v->s : nullptr;
    }
};

static void benc(const BVal& v, std::string& o) {
    switch (v.t) {
    case BVal::Int: o += 'i' + std::to_string(v.i) + 'e'; break;
    case BVal::Str: o += std::to_string(v.s.size()) + ':' + v.s; break;
    case BVal::List: o += 'l'; for (auto& x : v.l) benc(x, o); o += 'e'; break;
    case BVal::Dict: o += 'd'; for (auto& [k, x] : v.d) { o += std::to_string(k.size()) + ':' + k; benc(x, o); } o += 'e'; break;
    }
}

static bool bdec(const std::string& in, size_t& p, BVal& out, int depth) {
    if (depth > 16 || p >= in.size()) return false;
    char c = in[p];
    if (c == 'i') {
        size_t e = in.find('e', p);
        if (e == std::string::npos || e - p > 21) return false;
        try { out = BVal(int64_t(std::stoll(in.substr(p + 1, e - p - 1)))); } catch (...) { return false; }
        p = e + 1;
        return true;
    }
    if (c == 'l' || c == 'd') {
        out = BVal();
        out.t = c == 'l' ? BVal::List : BVal::Dict;
        p++;
        while (p < in.size() && in[p] != 'e') {
            if (out.t == BVal::List) {
                BVal x;
                if (!bdec(in, p, x, depth + 1)) return false;
                out.l.push_back(std::move(x));
            } else {
                BVal k, x;
                if (!bdec(in, p, k, depth + 1) || k.t != BVal::Str || !bdec(in, p, x, depth + 1)) return false;
                out.d[k.s] = std::move(x);
            }
        }
        if (p >= in.size()) return false;
        p++;
        return true;
    }
    if (c >= '0' && c <= '9') {
        size_t colon = in.find(':', p);
        if (colon == std::string::npos || colon - p > 8) return false;
        size_t n = size_t(std::stoul(in.substr(p, colon - p)));
        if (colon + 1 + n > in.size()) return false;
        out = BVal(in.substr(colon + 1, n));
        p = colon + 1 + n;
        return true;
    }
    return false;
}

static std::string compact_addr(const NetAddr& a) {
    std::string s(6, '\0');
    s[0] = char(a.ip >> 24); s[1] = char(a.ip >> 16); s[2] = char(a.ip >> 8); s[3] = char(a.ip);
    s[4] = char(a.port >> 8); s[5] = char(a.port);
    return s;
}
static NetAddr parse_compact(const std::string& s, size_t off) {
    const uint8_t* b = (const uint8_t*)s.data() + off;
    NetAddr a;
    a.ip = uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3];
    a.port = uint16_t(b[4] << 8 | b[5]);
    return a;
}
static std::string xor_dist(const std::string& a, const std::string& b) {
    std::string d(20, '\0');
    for (int i = 0; i < 20; i++) d[i] = char(uint8_t(a[i]) ^ uint8_t(b[i]));
    return d;
}

// ---------------------------------------------------------------- Dht
Dht::Dht(const uint8_t infohash[20], uint16_t udp_port, uint16_t announce_port, const std::string& state_path)
    : infohash_((const char*)infohash, 20), port_(udp_port), announce_port_(announce_port), state_path_(state_path) {
    Hash256 r = random_hash();
    my_id_.assign((const char*)r.data(), 20);
    secret_.assign((const char*)random_hash().data(), 32);
    // Restore id + known nodes from last run (fast, server-free restart).
    FILE* f = fopen(state_path_.c_str(), "rb");
    if (f) {
        Bytes b(65536);
        size_t n = fread(b.data(), 1, b.size(), f);
        fclose(f);
        b.resize(n);
        try {
            Reader rd(b);
            Bytes id = rd.raw(20);
            my_id_.assign(id.begin(), id.end());
            size_t cnt = rd.varint_max(1000);
            for (size_t i = 0; i < cnt; i++) {
                Bytes nid = rd.raw(20);
                NetAddr a; a.ip = rd.u32le(); a.port = uint16_t(rd.u32le());
                add_node(std::string(nid.begin(), nid.end()), a);
            }
        } catch (...) {}
    }
}

Dht::~Dht() { save(); sock_close(sock_); }

void Dht::save() {
    Writer w;
    w.raw((const uint8_t*)my_id_.data(), 20);
    std::vector<Node> good;
    for (auto& [id, n] : nodes_) if (n.fails == 0) good.push_back(n);
    if (good.size() > 300) good.resize(300);
    w.varint(good.size());
    for (auto& n : good) { w.raw((const uint8_t*)n.id.data(), 20); w.u32le(n.addr.ip); w.u32le(n.addr.port); }
    FILE* f = fopen(state_path_.c_str(), "wb");
    if (f) { fwrite(w.buf.data(), 1, w.buf.size(), f); fclose(f); }
}

bool Dht::start(std::string* err) {
    sock_ = udp_bind(port_, false, err);
    return sock_ != BAD_SOCK;
}

std::string Dht::status() const {
    return std::to_string(nodes_.size()) + " DHT nodes, " + std::to_string(found_.size()) + " Quant peers found" +
           (lookup_active_ ? " (searching)" : "");
}

std::string Dht::token_for(const NetAddr& a) const {
    std::string s = secret_ + compact_addr(a);
    Hash256 h = blake3((const uint8_t*)s.data(), s.size());
    return std::string((const char*)h.data(), 8);
}

void Dht::add_node(const std::string& id, const NetAddr& a) {
    if (id.size() != 20 || id == my_id_ || !a.routable()) return;
    auto& n = nodes_[id];
    n.id = id;
    n.addr = a;
    n.last_seen = now_millis();
    n.fails = 0;
    if (nodes_.size() > 1500) {
        // drop a failing or random far node
        for (auto it = nodes_.begin(); it != nodes_.end(); ++it)
            if (it->second.fails > 0) { nodes_.erase(it); return; }
        nodes_.erase(nodes_.begin());
    }
}

std::vector<Dht::Node> Dht::closest(const std::string& target, size_t n) const {
    std::vector<Node> v;
    for (auto& [id, node] : nodes_) if (node.fails < 3) v.push_back(node);
    std::sort(v.begin(), v.end(), [&](auto& a, auto& b) { return xor_dist(a.id, target) < xor_dist(b.id, target); });
    if (v.size() > n) v.resize(n);
    return v;
}

void Dht::send_query(const NetAddr& to, const std::string& q, const std::map<std::string, std::string>& args, bool lookup) {
    if (sock_ == BAD_SOCK) return;
    uint16_t tid = next_tid_++;
    std::string t = {char(tid >> 8), char(tid)};
    BVal a = BVal::dict();
    a.d["id"] = BVal(my_id_);
    for (auto& [k, v] : args) {
        if (k == "port" || k == "implied_port") a.d[k] = BVal(int64_t(std::stoll(v)));
        else a.d[k] = BVal(v);
    }
    BVal m = BVal::dict();
    m.d["t"] = BVal(t);
    m.d["y"] = BVal(std::string("q"));
    m.d["q"] = BVal(q);
    m.d["a"] = a;
    std::string out;
    benc(m, out);
    sockaddr_in sa = to.to_sockaddr();
    sendto(sock_, out.data(), int(out.size()), 0, (sockaddr*)&sa, sizeof sa);
    pending_[t] = lookup;
    if (pending_.size() > 4000) pending_.erase(pending_.begin());
}

void Dht::bootstrap() {
    last_bootstrap_ = now_millis();
    static const std::pair<const char*, uint16_t> routers[] = {
        {"router.bittorrent.com", 6881}, {"dht.transmissionbt.com", 6881},
        {"router.utorrent.com", 6881}, {"dht.libtorrent.org", 25401},
    };
    for (auto& [h, p] : routers)
        for (auto& a : resolve(h, p)) send_query(a, "find_node", {{"target", my_id_}}, false);
    for (auto& n : closest(my_id_, 16)) send_query(n.addr, "find_node", {{"target", my_id_}}, false);
}

void Dht::start_lookup() {
    lookup_.clear();
    for (auto& n : closest(infohash_, 32)) lookup_[n.id] = LookupNode{n.id, n.addr};
    lookup_active_ = true;
    lookup_started_ = now_millis();
    last_lookup_ = lookup_started_;
}

void Dht::step_lookup() {
    std::vector<LookupNode*> v;
    for (auto& [id, n] : lookup_) v.push_back(&n);
    std::sort(v.begin(), v.end(), [&](auto* a, auto* b) { return xor_dist(a->id, infohash_) < xor_dist(b->id, infohash_); });
    int sent = 0, window = 0;
    for (auto* n : v) {
        if (++window > 24) break;
        if (n->queried) continue;
        n->queried = true;
        send_query(n->addr, "get_peers", {{"info_hash", infohash_}}, true);
        if (++sent >= 4) break;
    }
    bool pending_close = false;
    window = 0;
    for (auto* n : v) { if (++window > 16) break; if (!n->queried) pending_close = true; }
    if ((!pending_close && now_millis() - lookup_started_ > 4000) || now_millis() - lookup_started_ > 25000) finish_lookup();
}

void Dht::finish_lookup() {
    lookup_active_ = false;
    std::vector<LookupNode*> v;
    for (auto& [id, n] : lookup_) if (n.responded && !n.token.empty()) v.push_back(&n);
    std::sort(v.begin(), v.end(), [&](auto* a, auto* b) { return xor_dist(a->id, infohash_) < xor_dist(b->id, infohash_); });
    int announced = 0;
    for (auto* n : v) {
        if (announced >= 8 || !announce) break;
        send_query(n->addr, "announce_peer",
                   {{"info_hash", infohash_}, {"port", std::to_string(announce_port_)}, {"implied_port", "0"}, {"token", n->token}}, false);
        announced++;
    }
    if (announced) last_announce_ = now_millis();
    lookup_.clear();
}

void Dht::tick(int64_t now) {
    if (sock_ == BAD_SOCK) return;
    if ((nodes_.size() < 30 && now - last_bootstrap_ > 30000) || last_bootstrap_ == 0) bootstrap();
    int64_t interval = found_.empty() ? 30000 : 10 * 60000;
    if (!lookup_active_ && nodes_.size() >= 8 && now - last_lookup_ > interval) start_lookup();
    if (lookup_active_) step_lookup();
}

void Dht::on_readable() {
    char buf[2048];
    for (int k = 0; k < 64; k++) {
        sockaddr_in from{};
        socklen_t fl = sizeof from;
        int n = int(recvfrom(sock_, buf, sizeof buf, 0, (sockaddr*)&from, &fl));
        if (n <= 0) return;
        std::string s(buf, size_t(n));
        size_t p = 0;
        BVal m;
        if (!bdec(s, p, m, 0) || m.t != BVal::Dict) continue;
        handle(m, NetAddr::from_sockaddr(from));
    }
}

void Dht::handle(const BVal& m, const NetAddr& from) {
    const std::string* y = m.str("y");
    const std::string* t = m.str("t");
    if (!y || !t) return;
    if (*y == "r") {
        auto pit = pending_.find(*t);
        if (pit == pending_.end()) return;
        bool is_lookup = pit->second;
        pending_.erase(pit);
        const BVal* r = m.get("r");
        if (!r) return;
        const std::string* id = r->str("id");
        if (!id || id->size() != 20) return;
        add_node(*id, from);
        if (const std::string* ip = m.str("ip"); ip && ip->size() == 6 && on_my_ip) on_my_ip(parse_compact(*ip, 0));
        if (const std::string* nodes = r->str("nodes")) {
            for (size_t o = 0; o + 26 <= nodes->size(); o += 26) {
                std::string nid = nodes->substr(o, 20);
                NetAddr a = parse_compact(*nodes, o + 20);
                add_node(nid, a);
                if (is_lookup && lookup_active_ && a.routable() && nid != my_id_ && !lookup_.count(nid))
                    lookup_[nid] = LookupNode{nid, a};
            }
        }
        if (is_lookup && lookup_active_) {
            auto it = lookup_.find(*id);
            if (it != lookup_.end()) {
                it->second.responded = true;
                if (const std::string* tok = r->str("token")) it->second.token = *tok;
            }
            if (const BVal* vals = r->get("values"); vals && vals->t == BVal::List) {
                for (auto& v : vals->l) {
                    if (v.t != BVal::Str || v.s.size() != 6) continue;
                    NetAddr a = parse_compact(v.s, 0);
                    if (a.port == 0) continue;
                    bool fresh = found_.insert(a).second;
                    if (fresh) logf("DHT: found Quant peer %s", a.str().c_str());
                    if (on_peer) on_peer(a);
                }
            }
        }
        return;
    }
    if (*y != "q") return;
    const std::string* q = m.str("q");
    const BVal* a = m.get("a");
    if (!q || !a) return;
    const std::string* id = a->str("id");
    if (!id || id->size() != 20) return;
    add_node(*id, from);

    BVal r = BVal::dict();
    r.d["id"] = BVal(my_id_);
    auto nodes_for = [&](const std::string& target) {
        std::string c;
        for (auto& n : closest(target, 8)) c += n.id + compact_addr(n.addr);
        return c;
    };
    if (*q == "ping") {
    } else if (*q == "find_node") {
        const std::string* target = a->str("target");
        if (!target || target->size() != 20) return;
        r.d["nodes"] = BVal(nodes_for(*target));
    } else if (*q == "get_peers") {
        const std::string* ih = a->str("info_hash");
        if (!ih || ih->size() != 20) return;
        r.d["token"] = BVal(token_for(from));
        if (*ih == infohash_ && !stored_peers_.empty()) {
            BVal l; l.t = BVal::List;
            for (auto& p : stored_peers_) l.l.push_back(BVal(compact_addr(p)));
            r.d["values"] = l;
        } else {
            r.d["nodes"] = BVal(nodes_for(*ih));
        }
    } else if (*q == "announce_peer") {
        const std::string* ih = a->str("info_hash");
        const std::string* tok = a->str("token");
        if (!ih || !tok || *tok != token_for(from)) return;
        if (*ih == infohash_) {
            NetAddr p = from;
            const BVal* implied = a->get("implied_port");
            const BVal* port = a->get("port");
            if (!(implied && implied->t == BVal::Int && implied->i) && port && port->t == BVal::Int) p.port = uint16_t(port->i);
            if (std::find(stored_peers_.begin(), stored_peers_.end(), p) == stored_peers_.end()) {
                stored_peers_.push_back(p);
                if (stored_peers_.size() > 50) stored_peers_.erase(stored_peers_.begin());
            }
            if (found_.insert(p).second) logf("DHT: Quant peer %s announced to us", p.str().c_str());
            if (on_peer) on_peer(p);
        }
    } else {
        return;
    }
    BVal resp = BVal::dict();
    resp.d["t"] = BVal(*t);
    resp.d["y"] = BVal(std::string("r"));
    resp.d["r"] = r;
    resp.d["ip"] = BVal(compact_addr(from));
    std::string out;
    benc(resp, out);
    sockaddr_in sa = from.to_sockaddr();
    sendto(sock_, out.data(), int(out.size()), 0, (sockaddr*)&sa, sizeof sa);
}

} // namespace quant
