#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Wire format on \\.\pipe\DlpMonitor: [uint32 little-endian length][UTF-8 JSON].
// Each JSON message is {"type": "...", ...}:
//   agent -> tray: {"type":"event","event":{DlpEvent}}
//   tray -> agent: {"type":"clipboard","pid":N,"image":"...","text":"..."}
//                  {"type":"hello","session":N}
namespace dlp::pipe {

inline constexpr wchar_t kPipeName[] = LR"(\\.\pipe\DlpMonitor)";
inline constexpr uint32_t kMaxFrame = 1u << 20;

std::string encode_frame(std::string_view payload);

// Incremental decoder: feed raw bytes as they arrive from ReadFile, pull complete messages.
class FrameDecoder {
public:
    void feed(const char* data, size_t len);
    std::optional<std::string> next();
    // True once a frame header announced a size above kMaxFrame. The peer is then
    // untrusted and the connection should be dropped.
    bool corrupt() const { return corrupt_; }

private:
    std::vector<char> buf_;
    size_t pos_ = 0;
    bool corrupt_ = false;
};

}  // namespace dlp::pipe
