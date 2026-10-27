#include "agent/pipe_server.h"

#include <sddl.h>

#include <system_error>

#include "common/log.h"

namespace dlp {
namespace {

constexpr size_t kHistory = 100;
// SYSTEM and Administrators: full. Interactive users (IU): read/write, no WRITE_DAC etc.
constexpr wchar_t kPipeSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

}  // namespace

PipeServer::PipeServer(Handler handler, std::wstring name)
    : handler_(std::move(handler)), name_(std::move(name)), stop_event_(::CreateEventW(nullptr, TRUE, FALSE, nullptr)) {}

PipeServer::~PipeServer() { stop(); }

UniqueHandle PipeServer::create_instance(bool first) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(kPipeSddl, SDDL_REVISION_1, &sd, nullptr))
        throw std::system_error(static_cast<int>(::GetLastError()), std::system_category(), "SDDL");
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (first) open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    UniqueHandle h(::CreateNamedPipeW(name_.c_str(), open_mode,
                                      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                          PIPE_REJECT_REMOTE_CLIENTS,
                                      PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, &sa));
    const DWORD err = ::GetLastError();
    ::LocalFree(sd);
    if (!h) throw std::system_error(static_cast<int>(err), std::system_category(), "CreateNamedPipe");
    return h;
}

void PipeServer::start() {
    auto listening = create_instance(true);
    accept_thread_ = std::thread([this, h = std::move(listening)]() mutable {
        ::SetThreadDescription(::GetCurrentThread(), L"pipe-accept");
        accept_loop(std::move(h));
    });
    log::info("pipe server listening");
}

void PipeServer::stop() {
    ::SetEvent(stop_event_.get());
    if (accept_thread_.joinable()) accept_thread_.join();
    std::vector<Client> clients;
    {
        std::lock_guard lock(mu_);
        clients.swap(clients_);
    }
    for (auto& c : clients)
        if (c.thread.joinable()) c.thread.join();
}

void PipeServer::accept_loop(UniqueHandle listening) {
    UniqueHandle connect_event(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    while (true) {
        OVERLAPPED ov{};
        ov.hEvent = connect_event.get();
        ::ResetEvent(ov.hEvent);
        bool connected = false;
        if (::ConnectNamedPipe(listening.get(), &ov)) {
            connected = true;
        } else if (const DWORD err = ::GetLastError(); err == ERROR_PIPE_CONNECTED) {
            connected = true;  // client raced in between CreateNamedPipe and ConnectNamedPipe
        } else if (err == ERROR_IO_PENDING) {
            const HANDLE waits[] = {stop_event_.get(), ov.hEvent};
            if (::WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
                DWORD n = 0;
                ::CancelIoEx(listening.get(), &ov);
                ::GetOverlappedResult(listening.get(), &ov, &n, TRUE);
                return;
            }
            DWORD n = 0;
            connected = ::GetOverlappedResult(listening.get(), &ov, &n, FALSE) != FALSE;
        } else {
            log::error("ConnectNamedPipe failed: {}", err);
            if (::WaitForSingleObject(stop_event_.get(), 1000) == WAIT_OBJECT_0) return;
        }

        // Always keep one instance listening, so the pipe name never becomes free to squat.
        UniqueHandle next;
        try {
            next = create_instance(false);
        } catch (const std::exception& e) {
            log::error("{}", e.what());
            return;
        }
        if (connected) {
            ULONG pid = 0;
            ::GetNamedPipeClientProcessId(listening.get(), &pid);
            auto conn = std::make_shared<pipe::PipeConnection>(std::move(listening));
            reap_finished();
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::lock_guard lock(mu_);
            for (const auto& h : history_) conn->send(h);
            clients_.push_back({conn, std::thread([this, conn, pid, done] {
                                    ::SetThreadDescription(::GetCurrentThread(), L"pipe-client");
                                    serve(conn, pid);
                                    *done = true;
                                }),
                                done});
        }
        listening = std::move(next);
    }
}

void PipeServer::serve(std::shared_ptr<pipe::PipeConnection> conn, uint32_t pid) {
    log::info("tray client connected (pid {})", pid);
    conn->run(stop_event_.get(), [&](std::string raw) {
        try {
            handler_(nlohmann::json::parse(raw), pid);
        } catch (const std::exception& e) {
            log::warn("bad message from pipe client {}: {}", pid, e.what());
        }
    });
    log::info("tray client disconnected (pid {})", pid);
}

void PipeServer::reap_finished() {
    std::lock_guard lock(mu_);
    std::erase_if(clients_, [](Client& c) {
        if (!*c.done) return false;
        c.thread.join();
        return true;
    });
}

void PipeServer::publish(const DlpEvent& event) {
    const std::string payload = nlohmann::json{{"type", "event"}, {"event", event}}.dump();
    std::lock_guard lock(mu_);
    history_.push_back(payload);
    if (history_.size() > kHistory) history_.pop_front();
    for (const auto& c : clients_)
        if (!*c.done) c.conn->send(payload);
}

}  // namespace dlp
