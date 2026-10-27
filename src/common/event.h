#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace dlp {

enum class EventKind {
    ProcessStart,
    ProcessStop,
    FileWrite,      // a monitored file was written and closed
    NetworkUpload,  // a process sent more than the policy threshold
    Violation,      // a policy rule matched
    Clipboard,      // clipboard content reported by the tray app
    Status,         // agent health / informational
};

std::string_view to_string(EventKind kind);
EventKind event_kind_from_string(std::string_view s);

struct DetectorCount {
    std::string detector;
    size_t count = 0;
    std::vector<std::string> samples;  // masked, never raw sensitive data
};

// One event flowing agent -> tray / cloud. Strings are UTF-8 so the type
// serializes directly to JSON.
struct DlpEvent {
    EventKind kind = EventKind::Status;
    int64_t time_ms = 0;  // Unix epoch milliseconds
    uint32_t pid = 0;
    std::string image;    // process image path
    std::string target;   // file path, remote endpoint, or "clipboard"
    uint64_t bytes = 0;
    std::string channel;  // usb | clipboard | network
    std::string rule_id;
    std::string rule_name;
    std::string severity;  // low | medium | high
    std::string action;    // log | alert
    std::vector<DetectorCount> matches;
    std::string message;
};

int64_t now_ms();

void to_json(nlohmann::json& j, const DetectorCount& c);
void from_json(const nlohmann::json& j, DetectorCount& c);
void to_json(nlohmann::json& j, const DlpEvent& e);
void from_json(const nlohmann::json& j, DlpEvent& e);

}  // namespace dlp
