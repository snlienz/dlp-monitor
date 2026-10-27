#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "agent/detectors.h"
#include "common/event.h"

namespace dlp {

struct Rule {
    std::string id;
    std::string name;
    std::vector<std::string> channels;   // usb | clipboard | network
    std::vector<std::string> detectors;  // built-in names or keyword set names
    size_t min_matches = 1;              // total matches across the rule's detectors
    std::string severity = "medium";
    std::string action = "alert";
};

// Immutable once built; the engine swaps whole Policy objects on update so scans
// in flight keep a consistent view.
struct Policy {
    int version = 0;
    std::vector<Rule> rules;
    std::vector<std::wstring> monitored_paths;  // lower-case prefixes treated as the "usb" channel
    uint64_t scan_limit_bytes = 8u << 20;
    uint64_t network_upload_threshold_bytes = 50u << 20;
    std::vector<std::unique_ptr<Detector>> detectors;  // every detector referenced by a rule

    const Detector* find_detector(std::string_view name) const;

    // Throws std::runtime_error with a readable message on invalid input.
    static std::shared_ptr<const Policy> parse(std::string_view json_text);
};

class PolicyEngine {
public:
    explicit PolicyEngine(std::shared_ptr<const Policy> policy) : policy_(std::move(policy)) {}

    std::shared_ptr<const Policy> current() const { return policy_.load(); }
    void update(std::shared_ptr<const Policy> policy) { policy_.store(std::move(policy)); }

    // Runs every rule bound to `channel` against `text`. Returns one Violation event per
    // matching rule with kind, channel, rule fields and matches filled in; the caller adds
    // process / target context.
    std::vector<DlpEvent> evaluate(std::string_view channel, std::string_view text) const;

private:
    std::atomic<std::shared_ptr<const Policy>> policy_;
};

}  // namespace dlp
