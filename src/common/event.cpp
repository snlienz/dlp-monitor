#include "common/event.h"

#include <array>
#include <chrono>
#include <stdexcept>
#include <utility>

#include <nlohmann/json.hpp>

namespace dlp {
namespace {

constexpr std::array<std::pair<EventKind, std::string_view>, 7> kKindNames{{
    {EventKind::ProcessStart, "process_start"},
    {EventKind::ProcessStop, "process_stop"},
    {EventKind::FileWrite, "file_write"},
    {EventKind::NetworkUpload, "network_upload"},
    {EventKind::Violation, "violation"},
    {EventKind::Clipboard, "clipboard"},
    {EventKind::Status, "status"},
}};

}  // namespace

std::string_view to_string(EventKind kind) {
    for (const auto& [k, name] : kKindNames)
        if (k == kind) return name;
    return "unknown";
}

EventKind event_kind_from_string(std::string_view s) {
    for (const auto& [k, name] : kKindNames)
        if (name == s) return k;
    throw std::invalid_argument("unknown event kind");
}

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void to_json(nlohmann::json& j, const DetectorCount& c) {
    j = {{"detector", c.detector}, {"count", c.count}, {"samples", c.samples}};
}

void from_json(const nlohmann::json& j, DetectorCount& c) {
    j.at("detector").get_to(c.detector);
    j.at("count").get_to(c.count);
    c.samples = j.value("samples", std::vector<std::string>{});
}

void to_json(nlohmann::json& j, const DlpEvent& e) {
    j = {{"kind", to_string(e.kind)}, {"time_ms", e.time_ms}, {"pid", e.pid},
         {"image", e.image},          {"target", e.target},   {"bytes", e.bytes},
         {"channel", e.channel},      {"rule_id", e.rule_id}, {"rule_name", e.rule_name},
         {"severity", e.severity},    {"action", e.action},   {"matches", e.matches},
         {"message", e.message}};
}

void from_json(const nlohmann::json& j, DlpEvent& e) {
    e.kind = event_kind_from_string(j.at("kind").get<std::string>());
    e.time_ms = j.value("time_ms", int64_t{0});
    e.pid = j.value("pid", uint32_t{0});
    e.image = j.value("image", "");
    e.target = j.value("target", "");
    e.bytes = j.value("bytes", uint64_t{0});
    e.channel = j.value("channel", "");
    e.rule_id = j.value("rule_id", "");
    e.rule_name = j.value("rule_name", "");
    e.severity = j.value("severity", "");
    e.action = j.value("action", "");
    e.matches = j.value("matches", std::vector<DetectorCount>{});
    e.message = j.value("message", "");
}

}  // namespace dlp
