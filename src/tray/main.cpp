// DlpTray: per-user companion to the DlpAgent service.
//  - shows agent events live in a virtual ListView
//  - raises a tray balloon for violations whose policy action is "alert"
//  - forwards clipboard text to the agent (the session-0 service can't read it)
#include <windows.h>

#include <commctrl.h>
#include <shellapi.h>

#include <array>
#include <deque>
#include <format>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include "common/event.h"
#include "common/handle.h"
#include "common/wstr.h"
#include "tray/clipboard.h"
#include "tray/pipe_client.h"

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' " \
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

using dlp::DlpEvent;
using dlp::EventKind;

constexpr UINT WM_APP_EVENT = WM_APP + 1;  // lParam: DlpEvent* (receiver owns)
constexpr UINT WM_APP_STATE = WM_APP + 2;  // wParam: connected
constexpr UINT WM_APP_TRAY = WM_APP + 3;
constexpr UINT kTrayId = 1;
constexpr UINT kCmdShow = 100;
constexpr UINT kCmdExit = 101;
constexpr size_t kMaxRows = 2000;
constexpr size_t kMaxClipboardChars = 256 * 1024;

constexpr std::array<std::pair<const wchar_t*, int>, 7> kColumns{{
    {L"Time", 70}, {L"Type", 100}, {L"Severity", 65}, {L"Rule", 160},
    {L"Process", 160}, {L"Target", 260}, {L"Details", 360},
}};

struct Row {
    std::array<std::wstring, kColumns.size()> cols;
    bool violation = false;
};

struct App {
    HINSTANCE instance = nullptr;
    HWND hwnd = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    UINT taskbar_created = 0;
    std::deque<Row> rows;  // newest at the back; displayed newest first
    std::unique_ptr<dlp::tray::PipeClient> client;
    bool connected = false;
    size_t violations = 0;
    std::wstring last_clipboard;
    bool exiting = false;
};
App g;

std::wstring local_time(int64_t ms) {
    // Unix ms -> FILETIME (100 ns since 1601) -> local SYSTEMTIME.
    const ULONGLONG ft = static_cast<ULONGLONG>(ms) * 10'000 + 116'444'736'000'000'000ULL;
    FILETIME utc{static_cast<DWORD>(ft), static_cast<DWORD>(ft >> 32)};
    SYSTEMTIME st_utc{}, st{};
    ::FileTimeToSystemTime(&utc, &st_utc);
    ::SystemTimeToTzSpecificLocalTime(nullptr, &st_utc, &st);
    return std::format(L"{:02}:{:02}:{:02}", st.wHour, st.wMinute, st.wSecond);
}

std::wstring basename(const std::string& path) {
    const auto w = dlp::to_wide(path);
    const auto slash = w.find_last_of(L"\\/");
    return slash == std::wstring::npos ? w : w.substr(slash + 1);
}

Row make_row(const DlpEvent& e) {
    Row r;
    r.violation = e.kind == EventKind::Violation;
    r.cols[0] = local_time(e.time_ms);
    r.cols[1] = dlp::to_wide(dlp::to_string(e.kind));
    r.cols[2] = dlp::to_wide(e.severity);
    r.cols[3] = dlp::to_wide(e.rule_name);
    r.cols[4] = e.pid ? std::format(L"{} ({})", basename(e.image), e.pid) : L"";
    r.cols[5] = dlp::to_wide(e.target);
    std::wstring details;
    for (const auto& m : e.matches) {
        if (!details.empty()) details += L"; ";
        details += std::format(L"{} x{}", dlp::to_wide(m.detector), m.count);
        if (!m.samples.empty()) details += L" (" + dlp::to_wide(m.samples.front()) + L")";
    }
    if (!e.message.empty()) details += (details.empty() ? L"" : L" - ") + dlp::to_wide(e.message);
    if (e.bytes && e.kind != EventKind::Violation) details += std::format(L" [{} bytes]", e.bytes);
    r.cols[6] = std::move(details);
    return r;
}

void set_tray(DWORD message, const wchar_t* balloon_title = nullptr, const std::wstring& balloon = {}) {
    NOTIFYICONDATAW nid{sizeof(nid)};
    nid.hWnd = g.hwnd;
    nid.uID = kTrayId;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_APP_TRAY;
    nid.hIcon = ::LoadIconW(nullptr, g.connected ? IDI_SHIELD : IDI_WARNING);
    wcsncpy_s(nid.szTip, g.connected ? L"DLP Monitor: protected" : L"DLP Monitor: agent not connected",
              _TRUNCATE);
    if (balloon_title) {
        nid.uFlags |= NIF_INFO;
        nid.dwInfoFlags = NIIF_WARNING | NIIF_RESPECT_QUIET_TIME;
        wcsncpy_s(nid.szInfoTitle, balloon_title, _TRUNCATE);
        wcsncpy_s(nid.szInfo, balloon.c_str(), _TRUNCATE);
    }
    ::Shell_NotifyIconW(message, &nid);
    if (message == NIM_ADD) {
        nid.uVersion = NOTIFYICON_VERSION_4;
        ::Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
}

void update_status() {
    const auto text = std::format(L"{}   |   {} events   |   {} violations",
                                  g.connected ? L"Connected to agent" : L"Agent not connected",
                                  g.rows.size(), g.violations);
    ::SendMessageW(g.status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(text.c_str()));
}

void add_event(std::unique_ptr<DlpEvent> e) {
    g.rows.push_back(make_row(*e));
    if (g.rows.size() > kMaxRows) g.rows.pop_front();
    ListView_SetItemCountEx(g.list, static_cast<int>(g.rows.size()), LVSICF_NOSCROLL);
    ::InvalidateRect(g.list, nullptr, FALSE);

    if (e->kind == EventKind::Violation) {
        ++g.violations;
        if (e->action == "alert") {
            const auto title = std::format(L"DLP: {}", dlp::to_wide(e->rule_name));
            const auto body = std::format(L"{} -> {}", basename(e->image), dlp::to_wide(e->target));
            set_tray(NIM_MODIFY, title.c_str(), body);
        }
    }
    update_status();
}

void on_clipboard_update() {
    auto clip = dlp::tray::read_clipboard_text(g.hwnd, kMaxClipboardChars);
    // Apps often re-announce the same content (multiple formats, delayed render); scan once.
    if (!clip || clip->text.empty() || clip->text == g.last_clipboard) return;
    g.last_clipboard = clip->text;
    const nlohmann::json msg{{"type", "clipboard"}, {"pid", clip->owner_pid}, {"text", dlp::to_utf8(clip->text)}};
    g.client->send(msg.dump());
}

void create_children(HWND hwnd) {
    g.status = ::CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0,
                                 0, hwnd, nullptr, g.instance, nullptr);
    g.list = ::CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                               WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL |
                                   LVS_SHOWSELALWAYS,
                               0, 0, 0, 0, hwnd, nullptr, g.instance, nullptr);
    ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    for (int i = 0; i < static_cast<int>(kColumns.size()); ++i) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(kColumns[static_cast<size_t>(i)].first);
        col.cx = kColumns[static_cast<size_t>(i)].second;
        ListView_InsertColumn(g.list, i, &col);
    }
}

void layout(HWND hwnd) {
    ::SendMessageW(g.status, WM_SIZE, 0, 0);
    RECT rc{}, sb{};
    ::GetClientRect(hwnd, &rc);
    ::GetWindowRect(g.status, &sb);
    ::MoveWindow(g.list, 0, 0, rc.right, rc.bottom - (sb.bottom - sb.top), TRUE);
}

void show_menu(HWND hwnd) {
    HMENU menu = ::CreatePopupMenu();
    ::AppendMenuW(menu, MF_STRING, kCmdShow, L"Show events");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kCmdExit, L"Exit");
    POINT pt{};
    ::GetCursorPos(&pt);
    ::SetForegroundWindow(hwnd);  // required, or the menu won't close when clicking elsewhere
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    ::DestroyMenu(menu);
}

void show_window(HWND hwnd) {
    ::ShowWindow(hwnd, SW_SHOW);
    ::ShowWindow(hwnd, SW_RESTORE);
    ::SetForegroundWindow(hwnd);
}

LRESULT on_notify(NMHDR* hdr) {
    if (hdr->hwndFrom != g.list) return 0;
    const auto index_to_row = [](int item) -> const Row* {
        if (item < 0 || static_cast<size_t>(item) >= g.rows.size()) return nullptr;
        return &g.rows[g.rows.size() - 1 - static_cast<size_t>(item)];
    };
    if (hdr->code == LVN_GETDISPINFOW) {
        auto* di = reinterpret_cast<NMLVDISPINFOW*>(hdr);
        const Row* row = index_to_row(di->item.iItem);
        if (row && (di->item.mask & LVIF_TEXT) && di->item.iSubItem < static_cast<int>(kColumns.size()))
            wcsncpy_s(di->item.pszText, di->item.cchTextMax,
                      row->cols[static_cast<size_t>(di->item.iSubItem)].c_str(), _TRUNCATE);
        return 0;
    }
    if (hdr->code == NM_CUSTOMDRAW) {
        auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(hdr);
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
            const Row* row = index_to_row(static_cast<int>(cd->nmcd.dwItemSpec));
            if (row && row->violation) {
                cd->clrTextBk = RGB(255, 225, 225);
                cd->clrText = RGB(120, 0, 0);
            }
            return CDRF_DODEFAULT;
        }
    }
    return 0;
}

LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == g.taskbar_created && g.taskbar_created != 0) {
        set_tray(NIM_ADD);  // Explorer restarted and lost our icon
        return 0;
    }
    switch (msg) {
        case WM_CREATE:
            g.hwnd = hwnd;
            create_children(hwnd);
            set_tray(NIM_ADD);
            ::AddClipboardFormatListener(hwnd);
            update_status();
            return 0;
        case WM_SIZE:
            layout(hwnd);
            return 0;
        case WM_NOTIFY:
            return on_notify(reinterpret_cast<NMHDR*>(lp));
        case WM_CLIPBOARDUPDATE:
            on_clipboard_update();
            return 0;
        case WM_APP_EVENT:
            add_event(std::unique_ptr<DlpEvent>(reinterpret_cast<DlpEvent*>(lp)));
            return 0;
        case WM_APP_STATE:
            g.connected = wp != 0;
            set_tray(NIM_MODIFY);
            update_status();
            return 0;
        case WM_APP_TRAY:
            switch (LOWORD(lp)) {
                case WM_CONTEXTMENU: show_menu(hwnd); break;
                case NIN_SELECT:
                case NIN_KEYSELECT:
                case NIN_BALLOONUSERCLICK: show_window(hwnd); break;
            }
            return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == kCmdShow) show_window(hwnd);
            if (LOWORD(wp) == kCmdExit) {
                g.exiting = true;
                ::DestroyWindow(hwnd);
            }
            return 0;
        case WM_CLOSE:
            if (!g.exiting) {
                ::ShowWindow(hwnd, SW_HIDE);  // closing the window keeps monitoring running
                return 0;
            }
            break;
        case WM_DESTROY:
            g.client->stop();
            ::RemoveClipboardFormatListener(hwnd);
            {
                NOTIFYICONDATAW nid{sizeof(nid)};
                nid.hWnd = hwnd;
                nid.uID = kTrayId;
                ::Shell_NotifyIconW(NIM_DELETE, &nid);
            }
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

int WINAPI wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int) {
    // One tray per session; a second launch just exits.
    dlp::UniqueHandle mutex(::CreateMutexW(nullptr, TRUE, L"Local\\DlpMonitorTray"));
    if (!mutex || ::GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES};
    ::InitCommonControlsEx(&icc);
    g.instance = instance;
    g.taskbar_created = ::RegisterWindowMessageW(L"TaskbarCreated");

    // Created before the window so WM_DESTROY can always stop it.
    g.client = std::make_unique<dlp::tray::PipeClient>(dlp::tray::PipeClient::Callbacks{
        [](bool connected) { ::PostMessageW(g.hwnd, WM_APP_STATE, connected, 0); },
        [](std::string raw) {
            try {
                const auto j = nlohmann::json::parse(raw);
                if (j.value("type", "") != "event") return;
                auto e = std::make_unique<DlpEvent>(j.at("event").get<DlpEvent>());
                if (::PostMessageW(g.hwnd, WM_APP_EVENT, 0, reinterpret_cast<LPARAM>(e.get())))
                    e.release();  // ownership passes to the UI thread
            } catch (const std::exception&) {
                // Ignore malformed messages; the agent is the only writer.
            }
        },
    });

    WNDCLASSEXW wc{sizeof(wc)};
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = instance;
    wc.hIcon = ::LoadIconW(nullptr, IDI_SHIELD);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"DlpMonitorTray";
    ::RegisterClassExW(&wc);

    HWND hwnd = ::CreateWindowExW(0, wc.lpszClassName, L"DLP Monitor", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                  CW_USEDEFAULT, 1200, 600, nullptr, nullptr, instance, nullptr);
    if (!hwnd) return 1;
    g.client->start();
    // Start hidden in the tray; pass --show to open the window immediately.
    if (wcsstr(::GetCommandLineW(), L"--show")) show_window(hwnd);

    MSG msg;
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
    // Events posted after the window died are still owned by the queue; free them.
    while (::PeekMessageW(&msg, nullptr, WM_APP_EVENT, WM_APP_EVENT, PM_REMOVE))
        delete reinterpret_cast<DlpEvent*>(msg.lParam);
    return 0;
}
