#pragma once
#include <windows.h>

#include <evntcons.h>
#include <evntrace.h>

#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace dlp {

// Manifest-based kernel providers. They can be enabled in a private real-time session,
// unlike the classic "NT Kernel Logger" which is a single machine-wide session.
inline constexpr GUID kKernelProcessProvider = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
inline constexpr GUID kKernelFileProvider = {
    0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}};
inline constexpr GUID kKernelNetworkProvider = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

struct EtwProvider {
    GUID guid;
    ULONGLONG keywords = 0;
    UCHAR level = TRACE_LEVEL_INFORMATION;
    // When non-empty, only these event IDs are delivered. The filter is applied inside ETW,
    // so dropped events never cost a buffer copy or a callback.
    std::vector<USHORT> event_ids;
};

struct EtwStats {
    ULONG events_lost = 0;
    ULONG buffers_lost = 0;
};

// Owns one real-time ETW session and the consumer thread that drains it.
// The callback runs on that single thread, in event order.
class EtwSession {
public:
    using Callback = std::function<void(const EVENT_RECORD&)>;

    EtwSession(std::wstring name, Callback callback);
    ~EtwSession();
    EtwSession(const EtwSession&) = delete;
    EtwSession& operator=(const EtwSession&) = delete;

    // Throws std::system_error. Requires administrator rights for kernel providers.
    void start(const std::vector<EtwProvider>& providers);
    void stop();
    EtwStats stats() const;

private:
    static void WINAPI on_event(PEVENT_RECORD record);
    void enable(const EtwProvider& p);

    std::wstring name_;
    Callback callback_;
    TRACEHANDLE session_ = 0;
    TRACEHANDLE consumer_ = INVALID_PROCESSTRACE_HANDLE;
    std::thread thread_;
};

}  // namespace dlp
