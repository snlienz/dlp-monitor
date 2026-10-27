#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace dlp {

// Sums bytes sent per (process, remote endpoint) in fixed windows and reports the first
// time a window crosses the threshold. One report per window keeps a long upload from
// producing an event per packet.
class NetworkTracker {
public:
    NetworkTracker(uint64_t threshold_bytes, int64_t window_ms)
        : threshold_(threshold_bytes), window_ms_(window_ms) {}

    void set_threshold(uint64_t bytes) { threshold_ = bytes; }

    // Returns the window total when this send makes it cross the threshold.
    std::optional<uint64_t> on_send(uint32_t pid, const std::string& remote, uint64_t bytes,
                                    int64_t now_ms);

    size_t tracked() const { return buckets_.size(); }

private:
    struct Bucket {
        int64_t window_start = 0;
        uint64_t bytes = 0;
        bool reported = false;
    };
    void prune(int64_t now_ms);

    std::unordered_map<std::string, Bucket> buckets_;
    uint64_t threshold_;
    int64_t window_ms_;
};

}  // namespace dlp
