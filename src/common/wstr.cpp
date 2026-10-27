#include "common/wstr.h"

#include <windows.h>

namespace dlp {

std::string to_utf8(std::wstring_view w) {
    if (w.empty()) return {};
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr,
                                          0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), len, nullptr,
                          nullptr);
    return out;
}

std::wstring to_wide(std::string_view s) {
    if (s.empty()) return {};
    const int len =
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(len), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
}

std::wstring to_lower(std::wstring_view s) {
    std::wstring out(s);
    if (!out.empty()) {
        ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, out.data(),
                        static_cast<int>(out.size()), out.data(), static_cast<int>(out.size()),
                        nullptr, nullptr, 0);
    }
    return out;
}

}  // namespace dlp
