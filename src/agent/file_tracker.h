#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace dlp {

// Correlates Kernel-File events by FILE_OBJECT pointer to find files that were written.
//
//   Create (12)  -> start tracking (caller only passes monitored paths)
//   Write  (16)  -> mark written, accumulate bytes
//   Cleanup (13) -> last user handle closed: report if written
//
// Cleanup is used rather than Close (14) because the cache manager holds its own reference
// to cached files, so Close can arrive minutes later or only at volume dismount.
//
// Only touched from the ETW consumer thread, so it needs no locking.
class FileTracker {
public:
    struct Written {
        std::wstring path;
        uint32_t pid = 0;
        uint64_t bytes = 0;
    };

    explicit FileTracker(size_t max_tracked = 8192) : max_tracked_(max_tracked) {}

    void on_create(uint64_t file_object, std::wstring path, uint32_t pid);
    void on_write(uint64_t file_object, uint64_t size);
    std::optional<Written> on_cleanup(uint64_t file_object);

    size_t tracked() const { return files_.size(); }
    size_t overflowed() const { return overflowed_; }

private:
    struct Entry {
        std::wstring path;
        uint32_t pid = 0;
        uint64_t bytes = 0;
        bool written = false;
    };
    std::unordered_map<uint64_t, Entry> files_;
    size_t max_tracked_;
    size_t overflowed_ = 0;
};

}  // namespace dlp
