// Automatic router port forwarding (UPnP IGD) so home nodes can accept inbound peers.
#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace quant {

class PortMapper {
public:
    PortMapper(uint16_t port) : port_(port) {}
    ~PortMapper() { stop(); }
    void start();
    void stop();
    std::string status() const { std::lock_guard l(mu_); return status_; }
    std::string external_ip() const { std::lock_guard l(mu_); return ext_ip_; }
    bool mapped() const { return mapped_; }

private:
    void run();
    uint16_t port_;
    std::thread th_;
    std::atomic<bool> stop_{false}, mapped_{false};
    mutable std::mutex mu_;
    std::string status_ = "not started", ext_ip_;
    std::string ctrl_url_, service_type_, lan_ip_;
};

} // namespace quant
