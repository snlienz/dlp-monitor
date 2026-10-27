#include "agent/policy_engine.h"

#include <algorithm>
#include <map>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "common/wstr.h"

namespace dlp {
namespace {

constexpr size_t kMaxSamplesPerDetector = 3;

bool valid_channel(const std::string& c) {
    return c == "usb" || c == "clipboard" || c == "network";
}

}  // namespace

const Detector* Policy::find_detector(std::string_view name) const {
    for (const auto& d : detectors)
        if (d->name() == name) return d.get();
    return nullptr;
}

std::shared_ptr<const Policy> Policy::parse(std::string_view json_text) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_text);
    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error(std::string("policy is not valid JSON: ") + e.what());
    }

    auto p = std::make_shared<Policy>();
    try {
        p->version = j.value("version", 0);
        p->scan_limit_bytes = j.value("scan_limit_bytes", p->scan_limit_bytes);
        p->network_upload_threshold_bytes =
            j.value("network_upload_threshold_bytes", p->network_upload_threshold_bytes);
        for (const auto& path : j.value("monitored_paths", std::vector<std::string>{}))
            p->monitored_paths.push_back(to_lower(to_wide(path)));

        std::map<std::string, std::vector<std::string>> keyword_sets;
        if (j.contains("keywords")) keyword_sets = j["keywords"].get<decltype(keyword_sets)>();

        for (const auto& jr : j.at("rules")) {
            Rule r;
            jr.at("id").get_to(r.id);
            r.name = jr.value("name", r.id);
            jr.at("channels").get_to(r.channels);
            jr.at("detectors").get_to(r.detectors);
            r.min_matches = std::max<size_t>(1, jr.value("min_matches", size_t{1}));
            r.severity = jr.value("severity", r.severity);
            r.action = jr.value("action", r.action);

            for (const auto& c : r.channels)
                if (!valid_channel(c))
                    throw std::runtime_error("rule " + r.id + ": unknown channel '" + c + "'");

            for (const auto& name : r.detectors) {
                if (p->find_detector(name)) continue;
                if (auto d = make_builtin_detector(name)) {
                    p->detectors.push_back(std::move(d));
                } else if (auto it = keyword_sets.find(name); it != keyword_sets.end()) {
                    p->detectors.push_back(make_keyword_detector(name, it->second));
                } else {
                    throw std::runtime_error("rule " + r.id + ": unknown detector '" + name + "'");
                }
            }
            p->rules.push_back(std::move(r));
        }
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error(std::string("policy schema error: ") + e.what());
    }
    return p;
}

std::vector<DlpEvent> PolicyEngine::evaluate(std::string_view channel, std::string_view text) const {
    const auto policy = current();
    std::vector<DlpEvent> out;
    if (!policy || text.empty()) return out;

    // Each detector runs at most once per call even when several rules reference it.
    std::map<const Detector*, std::vector<Match>> cache;
    auto matches_for = [&](const Detector* d) -> const std::vector<Match>& {
        auto [it, inserted] = cache.try_emplace(d);
        if (inserted) d->scan(text, it->second);
        return it->second;
    };

    for (const auto& rule : policy->rules) {
        if (std::find(rule.channels.begin(), rule.channels.end(), channel) == rule.channels.end())
            continue;

        DlpEvent ev;
        size_t total = 0;
        for (const auto& name : rule.detectors) {
            const auto& m = matches_for(policy->find_detector(name));
            if (m.empty()) continue;
            DetectorCount dc{name, m.size(), {}};
            for (size_t i = 0; i < m.size() && i < kMaxSamplesPerDetector; ++i)
                dc.samples.push_back(m[i].masked);
            ev.matches.push_back(std::move(dc));
            total += m.size();
        }
        if (total < rule.min_matches) continue;

        ev.kind = EventKind::Violation;
        ev.time_ms = now_ms();
        ev.channel = std::string(channel);
        ev.rule_id = rule.id;
        ev.rule_name = rule.name;
        ev.severity = rule.severity;
        ev.action = rule.action;
        out.push_back(std::move(ev));
    }
    return out;
}

}  // namespace dlp
