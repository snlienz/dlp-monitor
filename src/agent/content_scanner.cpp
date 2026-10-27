#include "agent/content_scanner.h"

#include <windows.h>

#include <algorithm>

#include "common/handle.h"
#include "common/wstr.h"

namespace dlp {
namespace {

std::string utf16_to_utf8(std::string_view bytes, bool big_endian) {
    std::wstring w(bytes.size() / 2, L'\0');
    for (size_t i = 0; i < w.size(); ++i) {
        const auto lo = static_cast<unsigned char>(bytes[2 * i + (big_endian ? 1 : 0)]);
        const auto hi = static_cast<unsigned char>(bytes[2 * i + (big_endian ? 0 : 1)]);
        w[i] = static_cast<wchar_t>(lo | (hi << 8));
    }
    return to_utf8(w);
}

}  // namespace

std::optional<std::string> decode_text(std::string_view b) {
    auto starts = [&](std::string_view prefix) { return b.substr(0, prefix.size()) == prefix; };
    if (starts("\xEF\xBB\xBF")) return std::string(b.substr(3));
    if (starts("\xFF\xFE")) return utf16_to_utf8(b.substr(2), false);
    if (starts("\xFE\xFF")) return utf16_to_utf8(b.substr(2), true);

    const auto sample = b.substr(0, 8192);
    const auto nuls = static_cast<size_t>(std::count(sample.begin(), sample.end(), '\0'));
    if (nuls == 0) return std::string(b);

    // BOM-less UTF-16LE text (common from PowerShell and some Windows tools) has NULs in
    // nearly every odd byte for ASCII-range content.
    size_t odd_nuls = 0;
    for (size_t i = 1; i < sample.size(); i += 2)
        if (sample[i] == '\0') ++odd_nuls;
    if (odd_nuls * 10 >= (sample.size() / 2) * 9 && odd_nuls >= nuls * 9 / 10)
        return utf16_to_utf8(b, false);
    return std::nullopt;
}

std::optional<std::string> read_file_prefix(const std::wstring& path, uint64_t limit) {
    UniqueHandle h;
    for (int attempt = 0; attempt < 5; ++attempt) {
        h.reset(::CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
        if (h || ::GetLastError() != ERROR_SHARING_VIOLATION) break;
        ::Sleep(100 * (attempt + 1));
    }
    if (!h) return std::nullopt;

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h.get(), &size)) return std::nullopt;
    const auto to_read = static_cast<size_t>(std::min<uint64_t>(static_cast<uint64_t>(size.QuadPart), limit));

    std::string buf(to_read, '\0');
    size_t got = 0;
    while (got < to_read) {
        DWORD n = 0;
        const auto chunk = static_cast<DWORD>(std::min<size_t>(to_read - got, 1u << 20));
        if (!::ReadFile(h.get(), buf.data() + got, chunk, &n, nullptr) || n == 0) break;
        got += n;
    }
    buf.resize(got);
    return buf;
}

}  // namespace dlp
