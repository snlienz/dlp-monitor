#pragma once
#include <string>

namespace dlp {

struct Config {
    std::wstring data_dir;     // %ProgramData%\DlpMonitor: synced policy, spool, logs
    std::wstring policy_path;  // explicit --policy, else data_dir\policy.json, else bundled default
    std::string cloud_url;     // e.g. http://127.0.0.1:8080; empty disables cloud sync
    std::string device_id;     // defaults to the computer name
    bool verbose = false;

    // Reads data_dir\agent.json if present ({"cloud_url": "...", "device_id": "..."}).
    static Config load_defaults();

    std::wstring synced_policy_path() const { return data_dir + L"\\policy.json"; }
    std::wstring spool_path() const { return data_dir + L"\\spool.jsonl"; }
    std::wstring log_path() const { return data_dir + L"\\agent.log"; }
};

std::wstring exe_dir();

// Creates data_dir with a DACL that lets only SYSTEM and Administrators write. Without
// this, ProgramData's inherited ACL would let any user replace the policy file.
bool ensure_data_dir(const std::wstring& dir);

}  // namespace dlp
