#pragma once
#include <windows.h>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "common/handle.h"
#include "common/pipe_connection.h"

namespace dlp::tray {

// Keeps a connection to the agent alive, reconnecting with backoff when the service
// restarts. Callbacks run on the client thread.
class PipeClient {
public:
    struct Callbacks {
        std::function<void(bool connected)> on_state;
        std::function<void(std::string message)> on_message;
    };

    explicit PipeClient(Callbacks cb);
    ~PipeClient();

    void start();
    void stop();
    // Returns false when not connected (message dropped).
    bool send(const std::string& payload);

private:
    void run();

    Callbacks cb_;
    UniqueHandle stop_event_;
    std::thread thread_;
    std::mutex mu_;
    std::shared_ptr<pipe::PipeConnection> conn_;
};

}  // namespace dlp::tray
