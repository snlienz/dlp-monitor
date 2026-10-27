#include "tray/clipboard.h"

#include <algorithm>

namespace dlp::tray {
namespace {

// Closes the clipboard on every return path; holding it open blocks every other app.
struct ClipboardLock {
    bool open = false;
    explicit ClipboardLock(HWND owner) {
        // Another process may hold it briefly right after it sent the update.
        for (int i = 0; i < 5 && !open; ++i) {
            open = ::OpenClipboard(owner) != FALSE;
            if (!open) ::Sleep(20);
        }
    }
    ~ClipboardLock() {
        if (open) ::CloseClipboard();
    }
};

}  // namespace

std::optional<ClipboardText> read_clipboard_text(HWND owner, size_t max_chars) {
    static const UINT exclude_format =
        ::RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing");
    if (exclude_format && ::IsClipboardFormatAvailable(exclude_format)) return std::nullopt;
    if (!::IsClipboardFormatAvailable(CF_UNICODETEXT)) return std::nullopt;

    ClipboardText result;
    if (HWND w = ::GetClipboardOwner()) ::GetWindowThreadProcessId(w, &result.owner_pid);
    // Delayed-rendering and some UWP sources have no owner window; the foreground app is the
    // best remaining guess at who copied.
    if (result.owner_pid == 0) ::GetWindowThreadProcessId(::GetForegroundWindow(), &result.owner_pid);

    ClipboardLock lock(owner);
    if (!lock.open) return std::nullopt;
    HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
    if (!data) return std::nullopt;
    const auto* text = static_cast<const wchar_t*>(::GlobalLock(data));
    if (!text) return std::nullopt;
    // GlobalSize bounds the scan: clipboard data isn't guaranteed to be NUL-terminated.
    const size_t cap = std::min(max_chars, ::GlobalSize(data) / sizeof(wchar_t));
    size_t n = 0;
    while (n < cap && text[n] != L'\0') ++n;
    result.text.assign(text, n);
    ::GlobalUnlock(data);
    return result;
}

}  // namespace dlp::tray
