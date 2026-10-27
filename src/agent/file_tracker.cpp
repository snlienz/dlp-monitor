#include "agent/file_tracker.h"

namespace dlp {

void FileTracker::on_create(uint64_t file_object, std::wstring path, uint32_t pid) {
    // FILE_OBJECT addresses are reused once freed, so a Create always replaces stale state
    // (e.g. if we missed the Cleanup because the event was lost).
    if (auto it = files_.find(file_object); it != files_.end()) {
        it->second = Entry{std::move(path), pid};
        return;
    }
    if (files_.size() >= max_tracked_) {
        ++overflowed_;
        return;
    }
    files_.emplace(file_object, Entry{std::move(path), pid});
}

void FileTracker::on_write(uint64_t file_object, uint64_t size) {
    if (auto it = files_.find(file_object); it != files_.end()) {
        it->second.written = true;
        it->second.bytes += size;
    }
}

std::optional<FileTracker::Written> FileTracker::on_cleanup(uint64_t file_object) {
    auto it = files_.find(file_object);
    if (it == files_.end()) return std::nullopt;
    Entry e = std::move(it->second);
    files_.erase(it);
    if (!e.written) return std::nullopt;
    return Written{std::move(e.path), e.pid, e.bytes};
}

}  // namespace dlp
