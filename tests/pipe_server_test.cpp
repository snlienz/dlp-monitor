#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <format>
#include <mutex>
#include <system_error>
#include <thread>

#include "agent/pipe_server.h"

namespace dlp {
namespace {

std::wstring unique_pipe_name() {
    return std::format(L"\\\\.\\pipe\\DlpMonitorTest-{}-{}", ::GetCurrentProcessId(), ::GetTickCount64());
}

// Collects messages delivered on another thread and lets the test wait for them.
template <class T>
struct Inbox {
    std::mutex mu;
    std::condition_variable cv;
    std::vector<T> items;

    void add(T v) {
        {
            std::lock_guard lock(mu);
            items.push_back(std::move(v));
        }
        cv.notify_all();
    }
    bool wait_for_count(size_t n) {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, std::chrono::seconds(5), [&] { return items.size() >= n; });
    }
};

TEST(PipeServer, HistoryBroadcastAndClientMessages) {
    const auto name = unique_pipe_name();
    Inbox<nlohmann::json> from_client;
    PipeServer server([&](const nlohmann::json& m, uint32_t pid) {
        EXPECT_EQ(pid, ::GetCurrentProcessId());
        from_client.add(m);
    }, name);
    server.start();

    DlpEvent before;
    before.kind = EventKind::Status;
    before.message = "before connect";
    server.publish(before);  // goes to history

    UniqueHandle h(::CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED, nullptr));
    ASSERT_TRUE(h) << ::GetLastError();
    pipe::PipeConnection client(std::move(h));
    UniqueHandle stop(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Inbox<nlohmann::json> to_client;
    std::thread pump([&] { client.run(stop.get(), [&](std::string raw) { to_client.add(nlohmann::json::parse(raw)); }); });

    ASSERT_TRUE(to_client.wait_for_count(1));
    EXPECT_EQ(to_client.items[0]["event"]["message"], "before connect");

    // History is sent under the same lock that registers the client, so it is now live.
    DlpEvent live;
    live.kind = EventKind::Violation;
    live.rule_id = "pci";
    server.publish(live);
    ASSERT_TRUE(to_client.wait_for_count(2));
    EXPECT_EQ(to_client.items[1]["event"]["kind"], "violation");

    client.send(R"({"type":"clipboard","pid":7,"text":"4111111111111111"})");
    ASSERT_TRUE(from_client.wait_for_count(1));
    EXPECT_EQ(from_client.items[0]["type"], "clipboard");

    ::SetEvent(stop.get());
    pump.join();
    server.stop();
}

TEST(PipeServer, SecondServerCannotTakeName) {
    const auto name = unique_pipe_name();
    PipeServer first([](const nlohmann::json&, uint32_t) {}, name);
    first.start();
    PipeServer squatter([](const nlohmann::json&, uint32_t) {}, name);
    EXPECT_THROW(squatter.start(), std::system_error);
    first.stop();
}

}  // namespace
}  // namespace dlp
