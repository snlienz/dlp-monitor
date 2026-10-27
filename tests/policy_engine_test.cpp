#include <gtest/gtest.h>

#include <stdexcept>

#include "agent/policy_engine.h"

namespace dlp {
namespace {

constexpr std::string_view kPolicy = R"({
  "version": 7,
  "monitored_paths": ["C:\\DlpTest\\"],
  "keywords": {"secret_words": ["project falcon"]},
  "rules": [
    {"id": "pci", "channels": ["usb", "clipboard"], "detectors": ["credit_card"], "severity": "high"},
    {"id": "emails", "channels": ["usb"], "detectors": ["email"], "min_matches": 3, "action": "log"},
    {"id": "falcon", "channels": ["clipboard"], "detectors": ["secret_words", "credit_card"]}
  ]
})";

TEST(Policy, ParsesFields) {
    const auto p = Policy::parse(kPolicy);
    EXPECT_EQ(p->version, 7);
    ASSERT_EQ(p->rules.size(), 3u);
    EXPECT_EQ(p->rules[0].name, "pci");  // name defaults to id
    EXPECT_EQ(p->rules[1].min_matches, 3u);
    ASSERT_EQ(p->monitored_paths.size(), 1u);
    EXPECT_EQ(p->monitored_paths[0], L"c:\\dlptest\\");
    EXPECT_EQ(p->detectors.size(), 3u);  // credit_card shared by two rules
}

TEST(Policy, RejectsBadInput) {
    EXPECT_THROW(Policy::parse("{"), std::runtime_error);
    EXPECT_THROW(Policy::parse(R"({"rules":[{"id":"x","channels":["fax"],"detectors":[]}]})"),
                 std::runtime_error);
    EXPECT_THROW(Policy::parse(R"({"rules":[{"id":"x","channels":["usb"],"detectors":["nope"]}]})"),
                 std::runtime_error);
    EXPECT_THROW(Policy::parse(R"({"rules":[{"channels":["usb"],"detectors":[]}]})"),
                 std::runtime_error);
}

TEST(PolicyEngine, MatchesOnlyRulesForChannel) {
    PolicyEngine engine(Policy::parse(kPolicy));
    const std::string text = "card 4111111111111111 for project Falcon";

    auto usb = engine.evaluate("usb", text);
    ASSERT_EQ(usb.size(), 1u);
    EXPECT_EQ(usb[0].rule_id, "pci");
    EXPECT_EQ(usb[0].severity, "high");
    EXPECT_EQ(usb[0].channel, "usb");
    ASSERT_EQ(usb[0].matches.size(), 1u);
    EXPECT_EQ(usb[0].matches[0].samples[0], "************1111");

    auto clip = engine.evaluate("clipboard", text);
    ASSERT_EQ(clip.size(), 2u);
    EXPECT_EQ(clip[1].rule_id, "falcon");
    EXPECT_EQ(clip[1].matches.size(), 2u);

    EXPECT_TRUE(engine.evaluate("network", text).empty());
}

TEST(PolicyEngine, MinMatchesThreshold) {
    PolicyEngine engine(Policy::parse(kPolicy));
    EXPECT_TRUE(engine.evaluate("usb", "a1@x.com a2@x.com").empty());
    auto v = engine.evaluate("usb", "a1@x.com a2@x.com a3@x.com");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0].action, "log");
    EXPECT_EQ(v[0].matches[0].count, 3u);
    EXPECT_EQ(v[0].matches[0].samples.size(), 3u);
}

TEST(PolicyEngine, UpdateSwapsPolicy) {
    PolicyEngine engine(Policy::parse(kPolicy));
    auto held = engine.current();
    engine.update(Policy::parse(R"({"version": 8, "rules": []})"));
    EXPECT_EQ(engine.current()->version, 8);
    EXPECT_EQ(held->version, 7);  // readers holding the old snapshot are unaffected
    EXPECT_TRUE(engine.evaluate("usb", "4111111111111111").empty());
}

}  // namespace
}  // namespace dlp
