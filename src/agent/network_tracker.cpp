#include "agent/network_tracker.h"

#include <format>

namespace dlp {

std::optional<uint64_t> NetworkTracker::on_send(uint32_t pid, const std::string& remote,
                                                uint64_t bytes, int64_t now_ms) {
    if (buckets_.size() > 4096) prune(now_ms);

    auto& b = buckets_[std::format("{}|{}", pid, remote)];
    if (now_ms - b.window_start >= window_ms_) b = Bucket{now_ms};
    b.bytes += bytes;
    if (!b.reported && b.bytes >= threshold_) {
        b.reported = true;
        return b.bytes;
    }
    return std::nullopt;
}

void NetworkTracker::prune(int64_t now_ms) {
    std::erase_if(buckets_, [&](const auto& kv) { return now_ms - kv.second.window_start >= window_ms_; });
}

}  // namespace dlp
