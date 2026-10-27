#include "agent/config.h"

#include <windows.h>

#include <sddl.h>
#include <shlobj.h>

#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "common/log.h"
#include "common/wstr.h"

namespace dlp {

std::wstring exe_dir() {
    wchar_t buf[MAX_PATH];
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    return path.substr(0, path.find_last_of(L'\\'));
}

Config Config::load_defaults() {
    Config c;
    PWSTR program_data = nullptr;
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &program_data))) {
        c.data_dir = std::wstring(program_data) + L"\\DlpMonitor";
        ::CoTaskMemFree(program_data);
    } else {
        c.data_dir = L"C:\\ProgramData\\DlpMonitor";
    }

    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = static_cast<DWORD>(std::size(name));
    if (::GetComputerNameW(name, &len)) c.device_id = to_utf8({name, len});

    std::ifstream f(c.data_dir + L"\\agent.json");
    if (f) {
        try {
            const auto j = nlohmann::json::parse(f);
            c.cloud_url = j.value("cloud_url", c.cloud_url);
            c.device_id = j.value("device_id", c.device_id);
            c.verbose = j.value("verbose", c.verbose);
        } catch (const std::exception& e) {
            log::warn("ignoring invalid agent.json: {}", e.what());
        }
    }
    return c;
}

bool ensure_data_dir(const std::wstring& dir) {
    // Protected DACL: SYSTEM and Administrators full control, Users read-only.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)", SDDL_REVISION_1, &sd, nullptr))
        return false;
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    const BOOL ok = ::CreateDirectoryW(dir.c_str(), &sa) || ::GetLastError() == ERROR_ALREADY_EXISTS;
    ::LocalFree(sd);
    return ok != FALSE;
}

}  // namespace dlp
