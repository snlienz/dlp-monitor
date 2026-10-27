#include "agent/cloud_client.h"

#include <cctype>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <format>

#include <nlohmann/json.hpp>

#include "common/log.h"

namespace dlp {
namespace {

using namespace std::chrono_literals;

constexpr size_t kBatchSize = 100;
constexpr auto kBatchLinger = 2s;
constexpr auto kPolicyPollInterval = 5min;  // fallback when the WebSocket is down
constexpr uint64_t kSpoolMaxBytes = 16u << 20;

std::string url_encode(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out.push_back(static_cast<char>(c));
        else
            out += std::format("%{:02X}", c);
    }
    return out;
}

}  // namespace

CloudClient::CloudClient(Options options)
    : opt_(std::move(options)),
      http_(std::make_unique<HttpClient>(opt_.base_url)),
      ws_http_(std::make_unique<HttpClient>(opt_.base_url)),
      spool_(opt_.spool_path, kSpoolMaxBytes) {}

CloudClient::~CloudClient() { stop(); }

void CloudClient::start() {
    sender_ = std::jthread([this](std::stop_token st) { sender_loop(st); });
    policy_ = std::jthread([this](std::stop_token st) { policy_loop(st); });
    websocket_ = std::jthread([this](std::stop_token st) { websocket_loop(st); });
    log::info("cloud client started for {}", opt_.base_url);
}

void CloudClient::stop() {
    for (auto* t : {&sender_, &policy_, &websocket_}) t->request_stop();
    outbox_.close();  // wakes the sender; it spools whatever is left
    ws_http_->close_websocket();
    for (auto* t : {&sender_, &policy_, &websocket_})
        if (t->joinable()) t->join();
}

void CloudClient::publish(const DlpEvent& event) {
    if (!outbox_.try_push(nlohmann::json(event).dump()))
        log::warn("cloud outbox full, event dropped");
}

void CloudClient::sleep_for(std::stop_token st, std::chrono::milliseconds d) {
    // Interruptible sleep: request_stop() wakes it immediately.
    std::mutex mu;
    std::condition_variable_any cv;
    std::unique_lock lock(mu);
    cv.wait_for(lock, st, d, [] { return false; });
}

bool CloudClient::post_batch(const std::vector<std::string>& lines) {
    std::string body = std::format(R"({{"device_id":{},"events":[)", nlohmann::json(opt_.device_id).dump());
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i) body += ',';
        body += lines[i];
    }
    body += "]}";
    const auto resp = http_->request(L"POST", "/api/v1/events", body);
    return resp && resp->status >= 200 && resp->status < 300;
}

void CloudClient::sender_loop(std::stop_token st) {
    ::SetThreadDescription(::GetCurrentThread(), L"cloud-sender");
    auto backoff = 1s;
    bool online = true;
    std::vector<std::string> batch;

    while (true) {
        // Gather a batch: block for the first event, then linger briefly for more.
        auto first = outbox_.pop();
        if (!first) break;  // closed and drained
        batch.push_back(std::move(*first));
        const auto deadline = std::chrono::steady_clock::now() + kBatchLinger;
        while (batch.size() < kBatchSize && !st.stop_requested()) {
            const auto left = deadline - std::chrono::steady_clock::now();
            if (left <= 0s) break;
            auto next = outbox_.pop_for(left);
            if (!next) break;
            batch.push_back(std::move(*next));
        }

        if (!st.stop_requested() && post_batch(batch)) {
            if (!online) log::info("cloud reachable again");
            online = true;
            backoff = 1s;
            // Drain the offline backlog now that the backend answers.
            auto spooled = spool_.load();
            size_t sent = 0;
            while (sent < spooled.size()) {
                const size_t n = std::min(kBatchSize, spooled.size() - sent);
                if (!post_batch({spooled.begin() + static_cast<std::ptrdiff_t>(sent),
                                 spooled.begin() + static_cast<std::ptrdiff_t>(sent + n)}))
                    break;
                sent += n;
            }
            if (sent > 0) {
                spool_.replace({spooled.begin() + static_cast<std::ptrdiff_t>(sent), spooled.end()});
                log::info("flushed {} spooled events", sent);
            }
        } else {
            if (online) log::warn("cloud unreachable, spooling events to disk");
            online = false;
            if (!spool_.append(batch)) log::error("spool full, {} events dropped", batch.size());
            if (!st.stop_requested()) {
                sleep_for(st, backoff);
                backoff = std::min(backoff * 2, std::chrono::seconds(60));
            }
        }
        batch.clear();
    }
}

void CloudClient::fetch_policy() {
    const int version = opt_.current_policy_version();
    const auto resp = http_->request(
        L"GET", std::format("/api/v1/policy?version={}&device_id={}", version, url_encode(opt_.device_id)));
    if (!resp) return;
    if (resp->status == 304) return;
    if (resp->status != 200) {
        log::warn("policy fetch returned HTTP {}", resp->status);
        return;
    }
    if (const auto err = opt_.apply_policy(resp->body); !err.empty())
        log::error("cloud policy rejected, keeping v{}: {}", version, err);
}

void CloudClient::policy_loop(std::stop_token st) {
    ::SetThreadDescription(::GetCurrentThread(), L"cloud-policy");
    auto last_fetch = std::chrono::steady_clock::now() - kPolicyPollInterval;
    while (!st.stop_requested()) {
        const auto now = std::chrono::steady_clock::now();
        if (fetch_requested_.exchange(false) || now - last_fetch >= kPolicyPollInterval) {
            fetch_policy();
            last_fetch = now;
        }
        sleep_for(st, 500ms);
    }
}

void CloudClient::websocket_loop(std::stop_token st) {
    ::SetThreadDescription(::GetCurrentThread(), L"cloud-ws");
    auto backoff = 1s;
    while (!st.stop_requested()) {
        const bool upgraded = ws_http_->run_websocket(
            std::format("/ws?device_id={}", url_encode(opt_.device_id)), [&](std::string msg) {
                try {
                    const auto j = nlohmann::json::parse(msg);
                    if (j.value("type", "") == "policy_updated") {
                        log::info("server announced policy v{}", j.value("version", 0));
                        fetch_requested_ = true;
                    }
                } catch (const std::exception& e) {
                    log::warn("bad websocket message: {}", e.what());
                }
            });
        if (upgraded) {
            backoff = 1s;
            fetch_requested_ = true;  // we may have missed a push while disconnected
        }
        sleep_for(st, backoff);
        backoff = std::min(backoff * 2, std::chrono::seconds(60));
    }
}

}  // namespace dlp
