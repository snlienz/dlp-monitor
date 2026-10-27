#pragma once
#include <string>
#include <string_view>

namespace dlp {

std::string to_utf8(std::wstring_view w);
std::wstring to_wide(std::string_view s);

// Lower-cases ASCII and Latin letters using the invariant locale; good enough for path compares.
std::wstring to_lower(std::wstring_view s);

}  // namespace dlp
