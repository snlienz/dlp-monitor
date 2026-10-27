// Integration test against server/mock_cloud.py. Skipped unless DLP_CLOUD_TEST_URL is set:
//   python server/mock_cloud.py --port 8099
//   set DLP_CLOUD_TEST_URL=http://127.0.0.1:8099 && ctest --preset debug -R Cloud
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <thread>

#include <nlohmann/json.hpp>

#include "agent/cloud_client.h"

namespace dlp {
namespace {

using namespace std::chrono_literals;

template <class Pred>
bool eventually(Pred pred, std::chrono::milliseconds timeout = 10s) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < end) {
        if (pred()) return true;
        std::this_thread::sleep_for(100ms);
    }
    return pred();
}

class CloudClientTest : public ::testing::Test {
protected:
    void SetUp() override {
        char buf[512]{};
        if (::GetEnvironmentVariableA("DLP_CLOUD_TEST_URL", buf, sizeof(buf)) == 0)
            GTEST_SKIP() << "DLP_CLOUD_TEST_URL not set";
        url_ = buf;
        device_ = std::format("test-{}-{}", ::GetCurrentProcessId(), ::GetTickCount64());
        spool_ = (std::filesystem::temp_directory_path() / (device_ + ".jsonl")).wstring();
    }
    void TearDown() override { std::filesystem::remove(spool_); }

    size_t events_for_device(HttpClient& http) {
        const auto resp = http.request(L"GET", "/api/v1/events?limit=5000");
        if (!resp || resp->status != 200) return 0;
        size_t n = 0;
        for (const auto& e : nlohmann::json::parse(resp->body))
            if (e.value("device_id", "") == device_) ++n;
        return n;
    }

    std::string url_, device_;
    std::wstring spool_;
};

TEST_F(CloudClientTest, SyncsPolicyAndUploadsEvents) {
    std::atomic<int> version{0};
    std::atomic<int> applied{0};
    CloudClient client({url_, device_, spool_, [&] { return version.load(); },
                        [&](const std::string& json) -> std::string {
                            version = nlohmann::json::parse(json).value("version", 0);
                            ++applied;
                            return {};
                        }});
    client.start();

    // Initial pull: our version 0 differs from the server's.
    ASSERT_TRUE(eventually([&] { return applied.load() >= 1; }));
    const int initial = version.load();

    for (int i = 0; i < 3; ++i) {
        DlpEvent e;
        e.kind = EventKind::Violation;
        e.time_ms = now_ms();
        e.rule_id = "pci";
        e.matches = {{"credit_card", 1, {"************1111"}}};
        client.publish(e);
    }
    HttpClient admin(url_);
    ASSERT_TRUE(eventually([&] { return events_for_device(admin) == 3; }));

    // Server push: updating the policy must reach us through the WebSocket, well before the
    // 5-minute polling fallback.
    ASSERT_TRUE(eventually([&] {
        const auto r = admin.request(L"GET", "/api/v1/devices");
        if (!r) return false;
        for (const auto& d : nlohmann::json::parse(r->body))
            if (d.value("device_id", "") == device_ && d.value("connected", false)) return true;
        return false;
    }));
    const auto policy = admin.request(L"GET", "/api/v1/policy");
    ASSERT_TRUE(policy && policy->status == 200);
    ASSERT_TRUE(admin.request(L"PUT", "/api/v1/policy", policy->body));
    EXPECT_TRUE(eventually([&] { return version.load() == initial + 1; }, 5s));

    client.stop();
}

TEST_F(CloudClientTest, SpoolsWhileOfflineAndFlushesLater) {
    // Port 9 (discard) is closed on a dev box: every POST fails and events must spool.
    {
        CloudClient offline({"http://127.0.0.1:9", device_, spool_, [] { return 0; },
                             [](const std::string&) { return std::string(); }});
        offline.start();
        DlpEvent e;
        e.kind = EventKind::Status;
        e.message = "spooled";
        offline.publish(e);
        ASSERT_TRUE(eventually([&] { return !Spool(spool_, 1 << 20).empty(); }));
        offline.stop();
    }

    CloudClient online({url_, device_, spool_, [] { return 0; }, [](const std::string&) { return std::string(); }});
    online.start();
    DlpEvent trigger;
    trigger.kind = EventKind::Status;
    trigger.message = "back online";
    online.publish(trigger);  // a successful POST triggers the spool flush

    HttpClient admin(url_);
    EXPECT_TRUE(eventually([&] { return events_for_device(admin) == 2; }));
    EXPECT_TRUE(Spool(spool_, 1 << 20).empty());
    online.stop();
}

}  // namespace
}  // namespace dlp
