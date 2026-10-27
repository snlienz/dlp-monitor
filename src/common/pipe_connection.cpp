#include "common/pipe_connection.h"

#include "common/log.h"
#include "common/pipe_protocol.h"

namespace dlp::pipe {
namespace {

constexpr DWORD kWriteTimeoutMs = 5000;

}  // namespace

PipeConnection::PipeConnection(UniqueHandle pipe, size_t max_pending)
    : pipe_(std::move(pipe)),
      read_event_(::CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      write_event_(::CreateEventW(nullptr, TRUE, FALSE, nullptr)),
      send_event_(::CreateEventW(nullptr, FALSE, FALSE, nullptr)),
      max_pending_(max_pending) {}

void PipeConnection::send(std::string_view payload) {
    auto frame = encode_frame(payload);
    {
        std::lock_guard lock(mu_);
        if (outbox_.size() >= max_pending_) {
            outbox_.pop_front();
            ++dropped_;
        }
        outbox_.push_back(std::move(frame));
    }
    ::SetEvent(send_event_.get());
}

size_t PipeConnection::dropped() const {
    std::lock_guard lock(mu_);
    return dropped_;
}

bool PipeConnection::flush_writes(HANDLE stop_event) {
    std::deque<std::string> batch;
    {
        std::lock_guard lock(mu_);
        batch.swap(outbox_);
    }
    for (const auto& frame : batch) {
        OVERLAPPED ov{};
        ov.hEvent = write_event_.get();
        ::ResetEvent(ov.hEvent);
        if (!::WriteFile(pipe_.get(), frame.data(), static_cast<DWORD>(frame.size()), nullptr, &ov) &&
            ::GetLastError() != ERROR_IO_PENDING)
            return false;

        const HANDLE waits[] = {stop_event, ov.hEvent};
        const DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, kWriteTimeoutMs);
        DWORD written = 0;
        if (w != WAIT_OBJECT_0 + 1 || !::GetOverlappedResult(pipe_.get(), &ov, &written, FALSE)) {
            // Stopped or the peer stopped reading. The OVERLAPPED lives on this stack frame,
            // so the I/O must be cancelled *and completed* before we return.
            ::CancelIoEx(pipe_.get(), &ov);
            ::GetOverlappedResult(pipe_.get(), &ov, &written, TRUE);
            return false;
        }
    }
    return true;
}

void PipeConnection::run(HANDLE stop_event, const std::function<void(std::string)>& on_message) {
    FrameDecoder decoder;
    char buf[8192];
    OVERLAPPED rov{};
    rov.hEvent = read_event_.get();

    auto issue_read = [&] {
        ::ResetEvent(rov.hEvent);
        return ::ReadFile(pipe_.get(), buf, sizeof(buf), nullptr, &rov) ||
               ::GetLastError() == ERROR_IO_PENDING;
    };

    bool read_pending = issue_read();
    bool ok = read_pending && flush_writes(stop_event);  // anything queued before run()
    while (ok) {
        const HANDLE waits[] = {stop_event, read_event_.get(), send_event_.get()};
        const DWORD w = ::WaitForMultipleObjects(3, waits, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0 + 1) {
            DWORD n = 0;
            read_pending = false;
            if (!::GetOverlappedResult(pipe_.get(), &rov, &n, FALSE)) break;  // peer gone
            decoder.feed(buf, n);
            while (auto msg = decoder.next()) on_message(std::move(*msg));
            if (decoder.corrupt()) {
                log::warn("pipe peer sent an oversized frame, disconnecting");
                break;
            }
            read_pending = issue_read();
            ok = read_pending;
        } else if (w == WAIT_OBJECT_0 + 2) {
            ok = flush_writes(stop_event);
        } else {
            break;  // stop requested, or the wait itself failed
        }
    }

    if (read_pending) {
        // Same rule as for writes: never let `rov` or `buf` go out of scope with I/O in flight.
        DWORD n = 0;
        ::CancelIoEx(pipe_.get(), &rov);
        ::GetOverlappedResult(pipe_.get(), &rov, &n, TRUE);
    }
}

}  // namespace dlp::pipe
