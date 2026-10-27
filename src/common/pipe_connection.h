#pragma once
#include <windows.h>

#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

#include "common/handle.h"

namespace dlp::pipe {

// One end of a framed, full-duplex named-pipe connection opened with FILE_FLAG_OVERLAPPED.
//
// A synchronous pipe handle serializes I/O: a ReadFile blocked waiting for the peer would
// also block every WriteFile on that handle. So run() keeps one overlapped read pending and
// interleaves queued writes from send(), all on the calling thread.
class PipeConnection {
public:
    explicit PipeConnection(UniqueHandle pipe, size_t max_pending = 512);
    PipeConnection(const PipeConnection&) = delete;
    PipeConnection& operator=(const PipeConnection&) = delete;

    // Thread-safe. Queues one message; when the peer is too slow the oldest is dropped.
    void send(std::string_view payload);

    // Pumps I/O until the peer disconnects, sends garbage, stalls a write, or `stop_event`
    // is signaled. `on_message` is invoked on this thread.
    void run(HANDLE stop_event, const std::function<void(std::string)>& on_message);

    HANDLE handle() const { return pipe_.get(); }
    size_t dropped() const;

private:
    bool flush_writes(HANDLE stop_event);

    UniqueHandle pipe_;
    UniqueHandle read_event_;
    UniqueHandle write_event_;
    UniqueHandle send_event_;  // auto-reset: "send() queued something"
    const size_t max_pending_;
    mutable std::mutex mu_;
    std::deque<std::string> outbox_;
    size_t dropped_ = 0;
};

}  // namespace dlp::pipe
