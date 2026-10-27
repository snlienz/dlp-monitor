#include "agent/etw_session.h"

#include <cstring>
#include <system_error>

#include "common/log.h"
#include "common/wstr.h"

namespace dlp {
namespace {

// EVENT_TRACE_PROPERTIES is variable-length: the session name is stored right after it.
struct PropertiesBuffer {
    explicit PropertiesBuffer(const std::wstring& name)
        : bytes(sizeof(EVENT_TRACE_PROPERTIES) + (name.size() + 1) * sizeof(wchar_t)) {
        auto* p = get();
        p->Wnode.BufferSize = static_cast<ULONG>(bytes.size());
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    }
    EVENT_TRACE_PROPERTIES* get() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(bytes.data()); }
    std::vector<unsigned char> bytes;
};

[[noreturn]] void throw_win32(ULONG err, const char* what) {
    throw std::system_error(static_cast<int>(err), std::system_category(), what);
}

ULONG stop_session(const std::wstring& name) {
    PropertiesBuffer props(name);
    return ::ControlTraceW(0, name.c_str(), props.get(), EVENT_TRACE_CONTROL_STOP);
}

}  // namespace

EtwSession::EtwSession(std::wstring name, Callback callback)
    : name_(std::move(name)), callback_(std::move(callback)) {}

EtwSession::~EtwSession() { stop(); }

void EtwSession::start(const std::vector<EtwProvider>& providers) {
    PropertiesBuffer props(name_);
    auto* p = props.get();
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;  // QueryPerformanceCounter timestamps
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->BufferSize = 64;  // KB
    p->MinimumBuffers = 16;
    p->MaximumBuffers = 128;
    p->FlushTimer = 1;  // seconds; bounds detection latency on quiet systems

    ULONG err = ::StartTraceW(&session_, name_.c_str(), p);
    if (err == ERROR_ALREADY_EXISTS) {
        // A previous instance crashed without stopping its session. Sessions outlive
        // processes, so reclaim it rather than failing forever.
        log::warn("ETW session {} already exists, stopping orphan", to_utf8(name_));
        stop_session(name_);
        PropertiesBuffer retry(name_);
        std::memcpy(retry.bytes.data(), props.bytes.data(), sizeof(EVENT_TRACE_PROPERTIES));
        err = ::StartTraceW(&session_, name_.c_str(), retry.get());
    }
    if (err != ERROR_SUCCESS) throw_win32(err, "StartTrace");

    try {
        for (const auto& provider : providers) enable(provider);

        EVENT_TRACE_LOGFILEW lf{};
        lf.LoggerName = name_.data();
        lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.EventRecordCallback = &EtwSession::on_event;
        lf.Context = this;
        consumer_ = ::OpenTraceW(&lf);
        if (consumer_ == INVALID_PROCESSTRACE_HANDLE) throw_win32(::GetLastError(), "OpenTrace");
    } catch (...) {
        stop();
        throw;
    }

    // ProcessTrace blocks until the session stops or the handle is closed.
    thread_ = std::thread([this] {
        ::SetThreadDescription(::GetCurrentThread(), L"etw-consumer");
        const ULONG rc = ::ProcessTrace(&consumer_, 1, nullptr, nullptr);
        if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
            log::error("ProcessTrace returned {}", rc);
    });
    log::info("ETW session {} started with {} providers", to_utf8(name_), providers.size());
}

void EtwSession::enable(const EtwProvider& provider) {
    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    std::vector<unsigned char> filter_buf;
    EVENT_FILTER_DESCRIPTOR desc{};
    if (!provider.event_ids.empty()) {
        filter_buf.resize(offsetof(EVENT_FILTER_EVENT_ID, Events) +
                          provider.event_ids.size() * sizeof(USHORT));
        auto* f = reinterpret_cast<EVENT_FILTER_EVENT_ID*>(filter_buf.data());
        f->FilterIn = TRUE;
        f->Count = static_cast<USHORT>(provider.event_ids.size());
        std::memcpy(f->Events, provider.event_ids.data(), provider.event_ids.size() * sizeof(USHORT));
        desc.Ptr = reinterpret_cast<ULONGLONG>(filter_buf.data());
        desc.Size = static_cast<ULONG>(filter_buf.size());
        desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
        params.EnableFilterDesc = &desc;
        params.FilterDescCount = 1;
    }

    ULONG err = ::EnableTraceEx2(session_, &provider.guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                 provider.level, provider.keywords, 0, 0, &params);
    if (err != ERROR_SUCCESS && params.FilterDescCount != 0) {
        // Older builds reject event-ID filters for some providers; the callback filters too.
        log::warn("EnableTraceEx2 with event filter failed ({}), retrying unfiltered", err);
        params.EnableFilterDesc = nullptr;
        params.FilterDescCount = 0;
        err = ::EnableTraceEx2(session_, &provider.guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                               provider.level, provider.keywords, 0, 0, &params);
    }
    if (err != ERROR_SUCCESS) throw_win32(err, "EnableTraceEx2");
}

void EtwSession::stop() {
    if (session_ != 0) {
        stop_session(name_);
        session_ = 0;
    }
    if (consumer_ != INVALID_PROCESSTRACE_HANDLE) {
        ::CloseTrace(consumer_);
        consumer_ = INVALID_PROCESSTRACE_HANDLE;
    }
    if (thread_.joinable()) {
        thread_.join();
        log::info("ETW session {} stopped", to_utf8(name_));
    }
}

EtwStats EtwSession::stats() const {
    PropertiesBuffer props(name_);
    EtwStats s;
    if (::ControlTraceW(0, name_.c_str(), props.get(), EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS) {
        s.events_lost = props.get()->EventsLost;
        s.buffers_lost = props.get()->RealTimeBuffersLost;
    }
    return s;
}

void WINAPI EtwSession::on_event(PEVENT_RECORD record) {
    auto* self = static_cast<EtwSession*>(record->UserContext);
    // Exceptions must not unwind into ETW's C frames.
    try {
        self->callback_(*record);
    } catch (const std::exception& e) {
        log::error("ETW callback threw: {}", e.what());
    }
}

}  // namespace dlp
