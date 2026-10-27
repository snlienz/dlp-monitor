#include "common/pipe_protocol.h"

#include <cstring>
#include <stdexcept>

namespace dlp::pipe {

std::string encode_frame(std::string_view payload) {
    if (payload.size() > kMaxFrame) throw std::length_error("frame too large");
    const auto len = static_cast<uint32_t>(payload.size());
    std::string out(4 + payload.size(), '\0');
    out[0] = static_cast<char>(len & 0xff);
    out[1] = static_cast<char>((len >> 8) & 0xff);
    out[2] = static_cast<char>((len >> 16) & 0xff);
    out[3] = static_cast<char>((len >> 24) & 0xff);
    std::memcpy(out.data() + 4, payload.data(), payload.size());
    return out;
}

void FrameDecoder::feed(const char* data, size_t len) {
    // Drop consumed bytes before growing so the buffer doesn't creep on long connections.
    if (pos_ > 0) {
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(pos_));
        pos_ = 0;
    }
    buf_.insert(buf_.end(), data, data + len);
}

std::optional<std::string> FrameDecoder::next() {
    if (corrupt_ || buf_.size() - pos_ < 4) return std::nullopt;
    const auto* p = reinterpret_cast<const unsigned char*>(buf_.data() + pos_);
    const uint32_t len = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
                         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    if (len > kMaxFrame) {
        corrupt_ = true;
        return std::nullopt;
    }
    if (buf_.size() - pos_ - 4 < len) return std::nullopt;
    std::string msg(buf_.data() + pos_ + 4, len);
    pos_ += 4 + len;
    if (pos_ == buf_.size()) {
        buf_.clear();
        pos_ = 0;
    }
    return msg;
}

}  // namespace dlp::pipe
