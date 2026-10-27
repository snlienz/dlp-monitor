#pragma once
#include <functional>

#include <windows.h>

namespace dlp {

inline constexpr wchar_t kServiceName[] = L"DlpMonitor";

// The body of the agent, shared by service and console modes: start everything, wait
// for `stop_event`, shut down. Returns a process exit code.
using AgentMain = std::function<int(HANDLE stop_event)>;

// Hands the process to the SCM. Returns once the service has stopped.
int run_as_service(AgentMain body);

// Runs in the foreground; Ctrl+C / console close signals stop.
int run_in_console(AgentMain body);

// Called by the body once startup has finished; no-op in console mode.
void report_running();

int install_service();
int uninstall_service();

}  // namespace dlp
