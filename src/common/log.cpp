#include "common/log.h"

#include <windows.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>

namespace dlp::log {
namespace {

struct State {
    std::mutex mu;
    bool console = false;
    Level level = Level::Info;
    std::ofstream file;
};

State& state() {
    static State s;
    return s;
}

const char* level_name(Level l) {
    switch (l) {
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO ";
        case Level::Warn: return "WARN ";
        case Level::Error: return "ERROR";
    }
    return "?";
}

}  // namespace

void set_console(bool enabled) {
    std::lock_guard lock(state().mu);
    state().console = enabled;
}

void open_file(const std::wstring& path) {
    std::lock_guard lock(state().mu);
    state().file.open(path, std::ios::app);
}

void set_level(Level level) {
    std::lock_guard lock(state().mu);
    state().level = level;
}

void write(Level level, std::string_view msg) {
    auto& s = state();
    const auto now = std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    const std::string line =
        std::format("{:%F %T} [{}] [{}] {}\n", now, level_name(level), ::GetCurrentThreadId(), msg);

    std::lock_guard lock(s.mu);
    if (level < s.level) return;
    ::OutputDebugStringA(line.c_str());
    if (s.console) std::fputs(line.c_str(), stderr);
    if (s.file.is_open()) s.file << line << std::flush;
}

}  // namespace dlp::log
