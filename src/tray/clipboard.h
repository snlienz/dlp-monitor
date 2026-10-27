#pragma once
#include <windows.h>

#include <optional>
#include <string>

namespace dlp::tray {

struct ClipboardText {
    std::wstring text;
    DWORD owner_pid = 0;  // process that put the data on the clipboard, when known
};

// Reads CF_UNICODETEXT, truncated to max_chars. Returns nullopt when there is no text, the
// clipboard is busy, or the source opted out with ExcludeClipboardContentFromMonitorProcessing
// (password managers set this; honouring it keeps secrets out of monitoring tools).
std::optional<ClipboardText> read_clipboard_text(HWND owner, size_t max_chars);

}  // namespace dlp::tray
