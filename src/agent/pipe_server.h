#pragma once
#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "agent/event_sink.h"
#include "common/handle.h"
#include "common/pipe_connection.h"
#include "common/pipe_protocol.h"

namespace dlp {

// Serves \\.\pipe\DlpMonitor to tray apps in user sessions.
//
//  * The DACL admits SYSTEM, Administrators and interactively logged-on users only, and
//    remote clients are rejected, so the pipe is not reachable over SMB.
//  * The first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE: if another process
//    already squats on the name (to impersonate the agent to the tray) start() fails.
//  * Each new client is first sent the recent event history.
class PipeServer final : public EventSink {
public:
    using Handler = std::function<void(const nlohmann::json& message, uint32_t client_pid)>;

    explicit PipeServer(Handler handler, std::wstring name = pipe::kPipeName);
    ~PipeServer() override;

    void start();  // throws std::system_error
    void stop();
    void publish(const DlpEvent& event) override;

private:
    struct Client {
        std::shared_ptr<pipe::PipeConnection> conn;
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    UniqueHandle create_instance(bool first);
    void accept_loop(UniqueHandle listening);
    void serve(std::shared_ptr<pipe::PipeConnection> conn, uint32_t pid);
    void reap_finished();

    Handler handler_;
    std::wstring name_;
    UniqueHandle stop_event_;
    std::thread accept_thread_;
    std::mutex mu_;
    std::vector<Client> clients_;
    std::deque<std::string> history_;
};

}  // namespace dlp
