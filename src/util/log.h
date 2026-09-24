// Tiny thread-safe logger. Lines go to stdout (optional) and a ring buffer the GUI can show.
#pragma once
#include <cstdio>
#include <deque>
#include <functional>
#include <mutex>
#include <string>

namespace quant {

void log_line(const std::string& s);
void log_set_file(const std::string& path);
void log_set_stdout(bool on);
std::deque<std::string> log_recent(size_t max = 500);

template <typename... Args>
void logf(const char* fmt, Args... args) {
    char buf[1024];
    if constexpr (sizeof...(Args) == 0) snprintf(buf, sizeof buf, "%s", fmt);
    else snprintf(buf, sizeof buf, fmt, args...);
    log_line(buf);
}

} // namespace quant
