#pragma once
#include "common/event.h"

namespace dlp {

// Consumers of agent events (log, tray pipe, cloud). publish() is called from scanner
// workers and the ETW thread, so implementations must be thread-safe and must not block:
// anything slow (pipe writes, HTTP) belongs on the sink's own thread.
class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void publish(const DlpEvent& event) = 0;
};

}  // namespace dlp
