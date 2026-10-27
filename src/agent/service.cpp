#include "agent/service.h"

#include <cstdio>
#include <string>

#include "agent/config.h"
#include "common/handle.h"
#include "common/log.h"

namespace dlp {
namespace {

// SCM callbacks take no context for ServiceMain, so service state is process-global.
struct ServiceState {
    AgentMain body;
    SERVICE_STATUS_HANDLE status_handle = nullptr;
    SERVICE_STATUS status{};
    UniqueHandle stop_event;
};
ServiceState g_service;

void set_status(DWORD state, DWORD exit_code = NO_ERROR, DWORD wait_hint_ms = 0) {
    static DWORD checkpoint = 1;
    auto& s = g_service.status;
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwWin32ExitCode = exit_code;
    s.dwWaitHint = wait_hint_ms;
    // Don't accept stop while starting: the agent can't be torn down half-built.
    s.dwControlsAccepted =
        state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    s.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    ::SetServiceStatus(g_service.status_handle, &s);
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            set_status(SERVICE_STOP_PENDING, NO_ERROR, 10'000);
            ::SetEvent(g_service.stop_event.get());
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_service.status_handle = ::RegisterServiceCtrlHandlerExW(kServiceName, control_handler, nullptr);
    if (!g_service.status_handle) return;
    set_status(SERVICE_START_PENDING, NO_ERROR, 15'000);

    g_service.stop_event.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    int rc = 1;
    try {
        // body() calls report_running() once the agent is up, then blocks on the event.
        rc = g_service.body(g_service.stop_event.get());
    } catch (const std::exception& e) {
        log::error("service body failed: {}", e.what());
    }
    set_status(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

BOOL WINAPI console_handler(DWORD) {
    ::SetEvent(g_service.stop_event.get());
    return TRUE;
}

struct ScHandle {
    SC_HANDLE h;
    explicit ScHandle(SC_HANDLE handle) : h(handle) {}
    ~ScHandle() {
        if (h) ::CloseServiceHandle(h);
    }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
};

int fail(const char* what) {
    std::fprintf(stderr, "%s failed: error %lu\n", what, ::GetLastError());
    return 1;
}

}  // namespace

void report_running() {
    if (g_service.status_handle) set_status(SERVICE_RUNNING);
}

int run_as_service(AgentMain body) {
    g_service.body = std::move(body);
    wchar_t name[] = L"DlpMonitor";
    const SERVICE_TABLE_ENTRYW table[] = {{name, service_main}, {nullptr, nullptr}};
    if (!::StartServiceCtrlDispatcherW(table)) {
        if (::GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            std::fprintf(stderr, "Not started by the SCM. Use --console to run interactively.\n");
        return fail("StartServiceCtrlDispatcher");
    }
    return 0;
}

int run_in_console(AgentMain body) {
    g_service.stop_event.reset(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
    ::SetConsoleCtrlHandler(console_handler, TRUE);
    return body(g_service.stop_event.get());
}

int install_service() {
    wchar_t exe[MAX_PATH];
    ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
    // Quoted so a path with spaces can't be hijacked (C:\Program.exe).
    const std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --service";

    ScHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!scm.h) return fail("OpenSCManager");
    ScHandle svc(::CreateServiceW(scm.h, kServiceName, L"DLP Monitor Agent", SERVICE_ALL_ACCESS,
                                  SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
    if (!svc.h) return fail("CreateService");

    wchar_t desc[] = L"Endpoint data loss prevention agent: monitors file, clipboard and network "
                     L"activity against DLP policy.";
    SERVICE_DESCRIPTIONW sd{desc};
    ::ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_DESCRIPTION, &sd);

    // Restart after 5 s on the first two crashes, then give up; reset the count daily.
    SC_ACTION actions[] = {{SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 5000}, {SC_ACTION_NONE, 0}};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 24 * 60 * 60;
    fa.cActions = static_cast<DWORD>(std::size(actions));
    fa.lpsaActions = actions;
    ::ChangeServiceConfig2W(svc.h, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    const auto config = Config::load_defaults();
    if (!ensure_data_dir(config.data_dir)) return fail("CreateDirectory(data dir)");
    std::printf("Service installed. Start with: sc start DlpMonitor\n");
    return 0;
}

int uninstall_service() {
    ScHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.h) return fail("OpenSCManager");
    ScHandle svc(::OpenServiceW(scm.h, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc.h) return fail("OpenService");

    SERVICE_STATUS status{};
    if (::ControlService(svc.h, SERVICE_CONTROL_STOP, &status)) {
        for (int i = 0; i < 30 && ::QueryServiceStatus(svc.h, &status) &&
                        status.dwCurrentState != SERVICE_STOPPED;
             ++i)
            ::Sleep(500);
    }
    if (!::DeleteService(svc.h)) return fail("DeleteService");
    std::printf("Service removed.\n");
    return 0;
}

}  // namespace dlp
