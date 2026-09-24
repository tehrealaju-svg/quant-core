// quant-cli - send commands to a running quantd. Example: quant-cli getinfo
#include <cstdio>
#include <fstream>

#include "node/httprpc.h"

using namespace quant;

int main(int argc, char** argv) {
    Network net = Network::Test;
    std::string datadir = default_datadir();
    uint16_t port = 0;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        std::string a = argv[i];
        if (a == "-testnet") net = Network::Test;
        else if (a == "-mainnet") net = Network::Main;
        else if (a == "-regtest") net = Network::Regtest;
        else if (a.rfind("-datadir=", 0) == 0) datadir = a.substr(9);
        else if (a.rfind("-rpcport=", 0) == 0) port = uint16_t(std::stoi(a.substr(9)));
        else { fprintf(stderr, "unknown option %s\n", a.c_str()); return 1; }
    }
    if (i >= argc) { fprintf(stderr, "usage: quant-cli [-testnet|-mainnet|-regtest] [-datadir=..] <command> [args...]\n       quant-cli help\n"); return 1; }
    const ChainParams& p = params_for(net);
    std::string method = argv[i++];
    json params = json::array();
    for (; i < argc; i++) {
        std::string a = argv[i];
        try {
            json j = json::parse(a);
            if (j.is_boolean() || j.is_array() || j.is_object()) { params.push_back(j); continue; }
        } catch (...) {}
        params.push_back(a); // numbers stay strings so amounts keep all 10 decimals
    }
    std::string token;
    std::ifstream(HttpRpcServer::cookie_path(datadir + "/" + p.name)) >> token;
    if (token.empty()) { fprintf(stderr, "error: quantd is not running (no .cookie in %s/%s)\n", datadir.c_str(), p.name.c_str()); return 1; }
    json result;
    std::string err;
    if (!http_rpc_call(port ? port : p.rpc_port, token, method, params, result, &err)) {
        fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    if (result.is_string()) printf("%s\n", result.get<std::string>().c_str());
    else printf("%s\n", result.dump(2).c_str());
    return 0;
}
