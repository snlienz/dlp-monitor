#pragma once
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace dlp {

// PID -> image path, fed by Kernel-Process start/stop events. Processes that started before
// the agent are resolved lazily with QueryFullProcessImageName and cached.
//
// Written by the ETW thread, read by scanner workers and the pipe server.
class ProcessTracker {
public:
    void on_start(uint32_t pid, std::wstring image);
    void on_stop(uint32_t pid);
    std::wstring image(uint32_t pid);

private:
    std::shared_mutex mu_;
    std::unordered_map<uint32_t, std::wstring> images_;
};

}  // namespace dlp
