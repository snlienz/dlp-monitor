#include <gtest/gtest.h>

#include <windows.h>

#include <filesystem>
#include <format>

#include "agent/spool.h"

namespace dlp {
namespace {

class SpoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        path_ = (std::filesystem::temp_directory_path() /
                 std::format("dlp-spool-{}-{}.jsonl", ::GetCurrentProcessId(), ::GetTickCount64()))
                    .wstring();
    }
    void TearDown() override { std::filesystem::remove(path_); }
    std::wstring path_;
};

TEST_F(SpoolTest, AppendLoadReplace) {
    Spool s(path_, 1 << 20);
    EXPECT_TRUE(s.empty());
    EXPECT_TRUE(s.append({R"({"a":1})", R"({"a":2})"}));
    EXPECT_TRUE(s.append({R"({"a":3})"}));
    EXPECT_FALSE(s.empty());
    auto lines = s.load();
    ASSERT_EQ(lines.size(), 3u);
    EXPECT_EQ(lines[2], R"({"a":3})");

    s.replace({lines[2]});  // first two were delivered
    EXPECT_EQ(s.load().size(), 1u);
    s.replace({});
    EXPECT_TRUE(s.empty());
}

TEST_F(SpoolTest, RefusesBeyondCap) {
    Spool s(path_, 20);
    EXPECT_TRUE(s.append({"0123456789"}));
    EXPECT_FALSE(s.append({"0123456789"}));  // 11 + 11 bytes > 20
    EXPECT_EQ(s.load().size(), 1u);
}

}  // namespace
}  // namespace dlp
