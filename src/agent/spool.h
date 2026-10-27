#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace dlp {

// Disk-backed backlog of serialized events (one JSON object per line) kept while the cloud
// is unreachable, so violations raised offline are still reported. Single-threaded: only
// the cloud sender thread uses it.
class Spool {
public:
    Spool(std::wstring path, uint64_t max_bytes) : path_(std::move(path)), max_bytes_(max_bytes) {}

    // Returns false when the spool is full and the lines were dropped.
    bool append(const std::vector<std::string>& lines);
    std::vector<std::string> load() const;
    // Atomically replaces the contents (write temp file, then rename).
    void replace(const std::vector<std::string>& lines);
    bool empty() const;

private:
    std::wstring path_;
    uint64_t max_bytes_;
};

}  // namespace dlp
