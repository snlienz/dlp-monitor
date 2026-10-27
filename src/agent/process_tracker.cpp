#include "agent/process_tracker.h"

#include <windows.h>

#include <mutex>

#include "common/handle.h"

namespace dlp {

void ProcessTracker::on_start(uint32_t pid, std::wstring image) {
    // A new start for a PID we already know means the PID was reused; overwrite.
    std::unique_lock lock(mu_);
    images_[pid] = std::move(image);
}

void ProcessTracker::on_stop(uint32_t pid) {
    std::unique_lock lock(mu_);
    images_.erase(pid);
}

std::wstring ProcessTracker::image(uint32_t pid) {
    {
        std::shared_lock lock(mu_);
        if (auto it = images_.find(pid); it != images_.end()) return it->second;
    }
    if (pid == 0) return L"Idle";
    if (pid == 4) return L"System";

    std::wstring path;
    UniqueHandle h(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (h) {
        wchar_t buf[MAX_PATH * 2];
        DWORD len = static_cast<DWORD>(std::size(buf));
        if (::QueryFullProcessImageNameW(h.get(), 0, buf, &len)) path.assign(buf, len);
    }
    if (!path.empty()) {
        std::unique_lock lock(mu_);
        images_.try_emplace(pid, path);
    }
    return path;
}

}  // namespace dlp
