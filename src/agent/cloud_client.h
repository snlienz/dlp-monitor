#pragma once
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "agent/event_sink.h"
#include "agent/http_client.h"
#include "agent/spool.h"
#include "common/bounded_queue.h"

namespace dlp {

// Talks to the management backend:
//   POST /api/v1/events          batched telemetry (spooled to disk while offline)
//   GET  /api/v1/policy?version  policy pull (304 when unchanged)
//   WS   /ws?device_id=          server push: {"type":"policy_updated","version":N}
//
// Only masked match samples ever leave the endpoint; raw file or clipboard content does not.
class CloudClient final : public EventSink {
public:
    struct Options {
        std::string base_url;
        std::string device_id;
        std::wstring spool_path;
        std::function<int()> current_policy_version;
        // Returns an error message, or empty on success.
        std::function<std::string(const std::string& policy_json)> apply_policy;
    };

    explicit CloudClient(Options options);
    ~CloudClient() override;

    void start();
    void stop();
    void publish(const DlpEvent& event) override;

private:
    void sender_loop(std::stop_token st);
    void policy_loop(std::stop_token st);
    void websocket_loop(std::stop_token st);
    bool post_batch(const std::vector<std::string>& lines);
    void fetch_policy();
    static void sleep_for(std::stop_token st, std::chrono::milliseconds d);

    Options opt_;
    std::unique_ptr<HttpClient> http_;     // REST, used by sender and policy threads
    std::unique_ptr<HttpClient> ws_http_;  // separate connection for the long-lived socket
    Spool spool_;
    BoundedQueue<std::string> outbox_{10'000};
    std::atomic<bool> fetch_requested_{true};
    std::jthread sender_;
    std::jthread policy_;
    std::jthread websocket_;
};

}  // namespace dlp
