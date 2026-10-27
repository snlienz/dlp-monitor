#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace dlp {

// Converts a file prefix to UTF-8 for the detectors. Handles UTF-8 (with or without BOM),
// UTF-16LE/BE with BOM, and BOM-less UTF-16LE. Returns nullopt for content that looks binary.
// Office/PDF containers are binary (zip/deflate) and would need format extractors.
std::optional<std::string> decode_text(std::string_view bytes);

// Reads up to `limit` bytes. Retries briefly on sharing violations, since the writer may
// still be releasing the file when Cleanup arrives.
std::optional<std::string> read_file_prefix(const std::wstring& path, uint64_t limit);

}  // namespace dlp
