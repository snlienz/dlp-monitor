#include <windows.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "agent/agent.h"
#include "agent/config.h"
#include "agent/service.h"
#include "common/log.h"
#include "common/wstr.h"

namespace {

class LogSink final : public dlp::EventSink {
public:
    void publish(const dlp::DlpEvent& e) override {
        if (e.kind == dlp::EventKind::Violation)
            dlp::log::warn("VIOLATION {}", nlohmann::json(e).dump());
        else
            dlp::log::info("{}", nlohmann::json(e).dump());
    }
};

void usage() {
    std::fprintf(stderr,
                 "DlpAgent - endpoint DLP monitor\n\n"
                 "  DlpAgent --console [--verbose] [--policy FILE] [--cloud URL]   run in foreground (admin)\n"
                 "  DlpAgent --install | --uninstall                               manage the service\n"
                 "  DlpAgent --service                                             entry point used by the SCM\n");
}

int agent_body(dlp::Config config, HANDLE stop_event) {
    dlp::ensure_data_dir(config.data_dir);
    dlp::log::open_file(config.log_path());
    if (config.verbose) dlp::log::set_level(dlp::log::Level::Debug);

    auto agent = std::make_unique<dlp::Agent>(config);
    agent->add_sink(std::make_shared<LogSink>());
    agent->start();
    dlp::report_running();
    dlp::log::info("agent running (device {})", config.device_id);

    ::WaitForSingleObject(stop_event, INFINITE);
    dlp::log::info("stop requested");
    agent->stop();
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::wstring> args(argv + 1, argv + argc);
    if (args.empty()) {
        usage();
        return 2;
    }

    auto config = dlp::Config::load_defaults();
    std::wstring mode;
    for (size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == L"--verbose") {
            config.verbose = true;
        } else if (a == L"--policy" && i + 1 < args.size()) {
            config.policy_path = args[++i];
        } else if (a == L"--cloud" && i + 1 < args.size()) {
            config.cloud_url = dlp::to_utf8(args[++i]);
        } else if (a.starts_with(L"--")) {
            mode = a;
        }
    }

    try {
        if (mode == L"--install") return dlp::install_service();
        if (mode == L"--uninstall") return dlp::uninstall_service();
        if (mode == L"--service")
            return dlp::run_as_service([config](HANDLE stop) { return agent_body(config, stop); });
        if (mode == L"--console") {
            dlp::log::set_console(true);
            return dlp::run_in_console([config](HANDLE stop) { return agent_body(config, stop); });
        }
    } catch (const std::exception& e) {
        dlp::log::error("fatal: {}", e.what());
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
    usage();
    return 2;
}
