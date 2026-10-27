#pragma once
#include <windows.h>

#include <evntcons.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include "agent/config.h"
#include "agent/etw_parser.h"
#include "agent/etw_session.h"
#include "agent/event_sink.h"
#include "agent/file_tracker.h"
#include "agent/network_tracker.h"
#include "agent/policy_engine.h"
#include "agent/process_tracker.h"
#include "agent/volume_map.h"
#include "common/bounded_queue.h"

namespace dlp {

// Wires ETW -> trackers -> scanner workers -> policy engine -> sinks.
//
// Threads:
//   etw-consumer  ETW callback: parse, correlate, enqueue. Never blocks or does I/O.
//   scan-N        read file / text, run detectors, publish
//   housekeeping  volume refresh, heartbeat
class Agent {
public:
    explicit Agent(Config config);
    ~Agent();

    // Sinks must be added before start().
    void add_sink(std::shared_ptr<EventSink> sink) { sinks_.push_back(std::move(sink)); }

    void start();
    void stop();

    // Queue text from another channel (clipboard via the tray app). Returns false if the
    // scan queue is full.
    bool submit_text(std::string channel, std::string text, uint32_t pid);

    // Validates and applies a new policy; throws std::runtime_error on invalid policy.
    void apply_policy(std::string_view json_text, bool persist);
    int policy_version() const { return engine_.current()->version; }

    void publish(const DlpEvent& event);

private:
    struct ScanFile {
        std::wstring path;
        uint32_t pid;
        uint64_t bytes;
    };
    struct ScanText {
        std::string channel;
        std::string text;
        uint32_t pid;
    };
    using Job = std::variant<ScanFile, ScanText>;

    void on_etw(const EVENT_RECORD& r);
    void on_process(const EVENT_RECORD& r);
    void on_file(const EVENT_RECORD& r);
    void on_network(const EVENT_RECORD& r);
    bool monitored(const ResolvedPath& p, const Policy& policy) const;

    void scan_worker();
    void handle(const ScanFile& job);
    void handle(const ScanText& job);
    void housekeeping(std::stop_token st);

    Config config_;
    PolicyEngine engine_;
    std::vector<std::shared_ptr<EventSink>> sinks_;

    VolumeMap volumes_;
    ProcessTracker processes_;
    FileTracker files_;        // ETW thread only
    NetworkTracker network_;   // ETW thread only
    EventParser parser_;       // ETW thread only
    BoundedQueue<Job> jobs_{1024};
    EtwSession etw_;
    std::vector<std::thread> workers_;
    std::jthread housekeeping_;
    std::mutex hk_mu_;
    std::condition_variable_any hk_cv_;

    const uint32_t self_pid_ = ::GetCurrentProcessId();
    std::atomic<uint64_t> etw_events_{0};
    std::atomic<uint64_t> files_scanned_{0};
    std::atomic<uint64_t> violations_{0};
};

}  // namespace dlp
