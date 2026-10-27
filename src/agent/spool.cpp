#include "agent/spool.h"

#include <windows.h>

#include <filesystem>
#include <fstream>

namespace dlp {

bool Spool::append(const std::vector<std::string>& lines) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path_, ec);
    uint64_t incoming = 0;
    for (const auto& l : lines) incoming += l.size() + 1;
    if (!ec && size + incoming > max_bytes_) return false;

    std::ofstream f(path_, std::ios::binary | std::ios::app);
    for (const auto& l : lines) f << l << '\n';
    return static_cast<bool>(f);
}

std::vector<std::string> Spool::load() const {
    std::vector<std::string> lines;
    std::ifstream f(path_, std::ios::binary);
    for (std::string line; std::getline(f, line);)
        if (!line.empty()) lines.push_back(std::move(line));
    return lines;
}

void Spool::replace(const std::vector<std::string>& lines) {
    if (lines.empty()) {
        ::DeleteFileW(path_.c_str());
        return;
    }
    const auto tmp = path_ + L".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        for (const auto& l : lines) f << l << '\n';
    }
    ::MoveFileExW(tmp.c_str(), path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

bool Spool::empty() const {
    std::error_code ec;
    return std::filesystem::file_size(path_, ec) == 0 || ec;
}

}  // namespace dlp
