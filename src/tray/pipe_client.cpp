#include "tray/pipe_client.h"

#include <algorithm>

#include <nlohmann/json.hpp>

#include "common/pipe_protocol.h"

namespace dlp::tray {

PipeClient::PipeClient(Callbacks cb)
    : cb_(std::move(cb)), stop_event_(::CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}

PipeClient::~PipeClient() { stop(); }

void PipeClient::start() {
    thread_ = std::thread([this] {
        ::SetThreadDescription(::GetCurrentThread(), L"pipe-client");
        run();
    });
}

void PipeClient::stop() {
    ::SetEvent(stop_event_.get());
    if (thread_.joinable()) thread_.join();
}

bool PipeClient::send(const std::string& payload) {
    std::lock_guard lock(mu_);
    if (!conn_) return false;
    conn_->send(payload);
    return true;
}

void PipeClient::run() {
    DWORD backoff_ms = 500;
    while (::WaitForSingleObject(stop_event_.get(), 0) == WAIT_TIMEOUT) {
        // SECURITY_IDENTIFICATION: the server may learn who we are but can't act as us.
        UniqueHandle h(::CreateFileW(pipe::kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                     OPEN_EXISTING,
                                     FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                                     nullptr));
        if (!h) {
            if (::GetLastError() == ERROR_PIPE_BUSY) {
                ::WaitNamedPipeW(pipe::kPipeName, 1000);
            } else {
                ::WaitForSingleObject(stop_event_.get(), backoff_ms);
                backoff_ms = std::min<DWORD>(backoff_ms * 2, 10'000);
            }
            continue;
        }
        backoff_ms = 500;

        auto conn = std::make_shared<pipe::PipeConnection>(std::move(h));
        DWORD session = 0;
        ::ProcessIdToSessionId(::GetCurrentProcessId(), &session);
        conn->send(nlohmann::json{{"type", "hello"}, {"session", session}}.dump());
        {
            std::lock_guard lock(mu_);
            conn_ = conn;
        }
        cb_.on_state(true);
        conn->run(stop_event_.get(), cb_.on_message);
        {
            std::lock_guard lock(mu_);
            conn_.reset();
        }
        cb_.on_state(false);
    }
}

}  // namespace dlp::tray
