#pragma once
#include <format>
#include <string>
#include <string_view>

namespace dlp::log {

enum class Level { Debug, Info, Warn, Error };

// Logs go to OutputDebugString always, to stderr when console output is enabled,
// and to a file when one is opened. Thread-safe.
void set_console(bool enabled);
void open_file(const std::wstring& path);
void set_level(Level level);
void write(Level level, std::string_view msg);

template <class... Args>
void debug(std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Debug, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void info(std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Info, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void warn(std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Warn, std::format(fmt, std::forward<Args>(args)...));
}
template <class... Args>
void error(std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Error, std::format(fmt, std::forward<Args>(args)...));
}

}  // namespace dlp::log
