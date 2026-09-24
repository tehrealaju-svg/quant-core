#include "net/upnp.h"

#include <chrono>

#include "util/log.h"

#ifdef QUANT_UPNP
#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>
#endif

namespace quant {

void PortMapper::start() {
    stop_ = false;
    th_ = std::thread([this] { run(); });
}

void PortMapper::stop() {
    stop_ = true;
    if (th_.joinable()) th_.join();
}

void PortMapper::run() {
#ifdef QUANT_UPNP
    auto set = [&](const std::string& s) { std::lock_guard l(mu_); status_ = s; };
    std::string port = std::to_string(port_);
    while (!stop_) {
        int err = 0;
        UPNPDev* devs = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, &err);
        UPNPUrls urls{};
        IGDdatas data{};
        char lan[64] = {0}, wan[64] = {0};
        int r = devs ? UPNP_GetValidIGD(devs, &urls, &data, lan, sizeof lan, wan, sizeof wan) : 0;
        if (r == 1) {
            char ext[40] = {0};
            if (UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, ext) == UPNPCOMMAND_SUCCESS) {
                std::lock_guard l(mu_);
                ext_ip_ = ext;
            }
            bool ok = true;
            for (const char* proto : {"TCP", "UDP"}) {
                int e = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, port.c_str(), port.c_str(), lan,
                                            "Quant node", proto, nullptr, "3600");
                if (e != UPNPCOMMAND_SUCCESS) { ok = false; logf("UPnP: %s mapping failed: %s", proto, strupnperror(e)); }
            }
            mapped_ = ok;
            if (ok) {
                set("port " + port + " forwarded via UPnP (external IP " + external_ip() + ")");
                logf("UPnP: %s", status().c_str());
                std::lock_guard l(mu_);
                ctrl_url_ = urls.controlURL;
                service_type_ = data.first.servicetype;
                lan_ip_ = lan;
            } else {
                set("router refused UPnP mapping - forward port " + port + " manually for inbound peers");
            }
        } else {
            set("no UPnP router found - forward port " + port + " manually for inbound peers");
        }
        if (r) FreeUPNPUrls(&urls);
        if (devs) freeUPNPDevlist(devs);
        // Refresh every 20 minutes (lease is 1 hour).
        for (int i = 0; i < 20 * 60 * 10 && !stop_; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (mapped_) {
        std::lock_guard l(mu_);
        for (const char* proto : {"TCP", "UDP"})
            UPNP_DeletePortMapping(ctrl_url_.c_str(), service_type_.c_str(), port.c_str(), proto, nullptr);
    }
#else
    std::lock_guard l(mu_);
    status_ = "UPnP not compiled in";
#endif
}

} // namespace quant
