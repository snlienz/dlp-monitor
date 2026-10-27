#include <gtest/gtest.h>

#include <nlohmann/json.hpp>

#include "common/event.h"

namespace dlp {
namespace {

TEST(DlpEvent, JsonRoundTrip) {
    DlpEvent e;
    e.kind = EventKind::Violation;
    e.time_ms = 1700000000000;
    e.pid = 1234;
    e.image = "C:\\Windows\\explorer.exe";
    e.target = "E:\\report.txt";
    e.bytes = 42;
    e.channel = "usb";
    e.rule_id = "pci";
    e.matches = {{"credit_card", 2, {"************1111"}}};

    const nlohmann::json j = e;
    EXPECT_EQ(j["kind"], "violation");
    const auto back = j.get<DlpEvent>();
    EXPECT_EQ(back.kind, EventKind::Violation);
    EXPECT_EQ(back.pid, 1234u);
    EXPECT_EQ(back.target, e.target);
    ASSERT_EQ(back.matches.size(), 1u);
    EXPECT_EQ(back.matches[0].count, 2u);
}

TEST(DlpEvent, UnknownKindThrows) {
    EXPECT_THROW(nlohmann::json({{"kind", "bogus"}}).get<DlpEvent>(), std::invalid_argument);
}

}  // namespace
}  // namespace dlp
