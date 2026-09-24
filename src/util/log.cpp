#include "util/log.h"

#include <ctime>

namespace quant {

static std::mutex g_mu;
static std::deque<std::string> g_ring;
static FILE* g_file = nullptr;
static bool g_stdout = true;

void log_set_file(const std::string& path) {
    std::lock_guard l(g_mu);
    if (g_file) fclose(g_file);
    g_file = fopen(path.c_str(), "a");
}
void log_set_stdout(bool on) { std::lock_guard l(g_mu); g_stdout = on; }

void log_line(const std::string& s) {
    time_t t = time(nullptr);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    std::string line = std::string(ts) + " " + s;
    std::lock_guard l(g_mu);
    if (g_stdout) { fputs(line.c_str(), stdout); fputc('\n', stdout); fflush(stdout); }
    if (g_file) { fputs(line.c_str(), g_file); fputc('\n', g_file); fflush(g_file); }
    g_ring.push_back(line);
    if (g_ring.size() > 2000) g_ring.pop_front();
}

std::deque<std::string> log_recent(size_t max) {
    std::lock_guard l(g_mu);
    if (g_ring.size() <= max) return g_ring;
    return std::deque<std::string>(g_ring.end() - max, g_ring.end());
}

} // namespace quant
