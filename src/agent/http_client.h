#pragma once
#include <windows.h>

#include <winhttp.h>

#include <functional>
#include <mutex>
#include <optional>
#include <string>

namespace dlp {

struct HttpResponse {
    DWORD status = 0;
    std::string body;
};

// Minimal synchronous WinHTTP wrapper for one base URL (http or https).
class HttpClient {
public:
    // Throws std::invalid_argument for an unparsable URL.
    explicit HttpClient(const std::string& base_url);
    ~HttpClient();
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // nullopt on transport failure (connection refused, timeout, TLS error...).
    std::optional<HttpResponse> request(const wchar_t* method, const std::string& path,
                                        const std::string& body = {});

    // Opens a WebSocket at `path` and calls on_message for each UTF-8 message until the
    // connection drops or close_websocket() is called from another thread. After
    // close_websocket() every later call returns immediately.
    // Returns false if the upgrade failed.
    bool run_websocket(const std::string& path, const std::function<void(std::string)>& on_message);
    void close_websocket();

private:
    HINTERNET open_request(const wchar_t* method, const std::string& path);

    HINTERNET session_ = nullptr;
    HINTERNET connect_ = nullptr;
    bool secure_ = false;
    std::mutex ws_mu_;
    HINTERNET ws_ = nullptr;
    bool shutdown_ = false;  // guarded by ws_mu_
};

}  // namespace dlp
