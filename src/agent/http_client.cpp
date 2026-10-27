#include "agent/http_client.h"

#include <stdexcept>
#include <vector>

#include "common/wstr.h"

namespace dlp {
namespace {

// Closes a WinHTTP handle on scope exit.
struct InternetHandle {
    HINTERNET h = nullptr;
    explicit InternetHandle(HINTERNET handle) : h(handle) {}
    ~InternetHandle() {
        if (h) ::WinHttpCloseHandle(h);
    }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
};

}  // namespace

HttpClient::HttpClient(const std::string& base_url) {
    const std::wstring url = to_wide(base_url);
    URL_COMPONENTS uc{sizeof(uc)};
    wchar_t host[256]{};
    uc.lpszHostName = host;
    uc.dwHostNameLength = static_cast<DWORD>(std::size(host));
    if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) throw std::invalid_argument("bad cloud URL: " + base_url);
    secure_ = uc.nScheme == INTERNET_SCHEME_HTTPS;

    session_ = ::WinHttpOpen(L"DlpAgent/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                             WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session_) throw std::runtime_error("WinHttpOpen failed");
    // resolve, connect, send, receive. Short enough that a dead backend doesn't stall shutdown.
    ::WinHttpSetTimeouts(session_, 5000, 5000, 10000, 10000);
    connect_ = ::WinHttpConnect(session_, host, uc.nPort, 0);
    if (!connect_) throw std::runtime_error("WinHttpConnect failed");
}

HttpClient::~HttpClient() {
    close_websocket();
    if (connect_) ::WinHttpCloseHandle(connect_);
    if (session_) ::WinHttpCloseHandle(session_);
}

HINTERNET HttpClient::open_request(const wchar_t* method, const std::string& path) {
    return ::WinHttpOpenRequest(connect_, method, to_wide(path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                WINHTTP_DEFAULT_ACCEPT_TYPES, secure_ ? WINHTTP_FLAG_SECURE : 0);
}

std::optional<HttpResponse> HttpClient::request(const wchar_t* method, const std::string& path,
                                                const std::string& body) {
    InternetHandle req(open_request(method, path));
    if (!req.h) return std::nullopt;

    const wchar_t* headers = body.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : L"Content-Type: application/json\r\n";
    if (!::WinHttpSendRequest(req.h, headers, static_cast<DWORD>(-1L),
                              body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
                              static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) ||
        !::WinHttpReceiveResponse(req.h, nullptr))
        return std::nullopt;

    HttpResponse resp;
    DWORD size = sizeof(resp.status);
    ::WinHttpQueryHeaders(req.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                          &resp.status, &size, WINHTTP_NO_HEADER_INDEX);
    DWORD avail = 0;
    while (::WinHttpQueryDataAvailable(req.h, &avail) && avail > 0) {
        const size_t old = resp.body.size();
        resp.body.resize(old + avail);
        DWORD read = 0;
        if (!::WinHttpReadData(req.h, resp.body.data() + old, avail, &read)) return std::nullopt;
        resp.body.resize(old + read);
    }
    return resp;
}

bool HttpClient::run_websocket(const std::string& path, const std::function<void(std::string)>& on_message) {
    HINTERNET ws = nullptr;
    {
        InternetHandle req(open_request(L"GET", path));
        // The upgrade option takes no buffer by design (documented usage), which /analyze flags.
#pragma warning(suppress : 6387)
        if (!req.h || !::WinHttpSetOption(req.h, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) ||
            !::WinHttpSendRequest(req.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !::WinHttpReceiveResponse(req.h, nullptr))
            return false;
        ws = ::WinHttpWebSocketCompleteUpgrade(req.h, 0);
        if (!ws) return false;
    }
    {
        std::lock_guard lock(ws_mu_);
        if (shutdown_) {
            // close_websocket() ran while we were upgrading; it had no handle to close.
            ::WinHttpCloseHandle(ws);
            return true;
        }
        ws_ = ws;
    }

    std::vector<char> buf(16 * 1024);
    std::string message;
    while (true) {
        {
            // close_websocket() may have run between two receives; don't touch a closed handle.
            std::lock_guard lock(ws_mu_);
            if (!ws_) return true;
        }
        DWORD read = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
        // Blocks until data arrives; closing the handle from another thread cancels it.
        if (::WinHttpWebSocketReceive(ws, buf.data(), static_cast<DWORD>(buf.size()), &read, &type) != NO_ERROR)
            break;
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) break;
        message.append(buf.data(), read);
        if (message.size() > (1u << 20)) break;  // a policy notification is tiny; refuse floods
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            on_message(std::move(message));
            message.clear();
        }
    }

    std::lock_guard lock(ws_mu_);
    if (ws_) {
        ::WinHttpCloseHandle(ws_);
        ws_ = nullptr;
    }
    return true;
}

void HttpClient::close_websocket() {
    std::lock_guard lock(ws_mu_);
    shutdown_ = true;
    if (ws_) {
        // Not WinHttpWebSocketClose: that waits for the server's close frame, which may never
        // come if the backend is dead. Closing the handle cancels the pending receive.
        ::WinHttpCloseHandle(ws_);
        ws_ = nullptr;
    }
}

}  // namespace dlp
