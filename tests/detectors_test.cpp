#include <gtest/gtest.h>

#include "agent/detectors.h"

namespace dlp {
namespace {

std::vector<Match> run(std::string_view detector, std::string_view text) {
    auto d = make_builtin_detector(detector);
    EXPECT_NE(d, nullptr);
    std::vector<Match> out;
    d->scan(text, out);
    return out;
}

TEST(Luhn, KnownNumbers) {
    EXPECT_TRUE(luhn_valid("4111111111111111"));
    EXPECT_TRUE(luhn_valid("378282246310005"));
    EXPECT_FALSE(luhn_valid("4111111111111112"));
    EXPECT_FALSE(luhn_valid(""));
    EXPECT_FALSE(luhn_valid("41a1"));
}

TEST(CreditCard, FindsSeparatedAndPlainNumbers) {
    const auto m = run("credit_card", "visa 4111 1111 1111 1111, mc 5500-0000-0000-0004 amex 378282246310005");
    ASSERT_EQ(m.size(), 3u);
    EXPECT_EQ(m[0].masked, "************1111");
    EXPECT_EQ(m[1].masked, "************0004");
    EXPECT_EQ(m[2].offset, std::string_view("visa 4111 1111 1111 1111, mc 5500-0000-0000-0004 amex ").size());
}

TEST(CreditCard, RejectsLuhnFailuresAndEmbeddedDigits) {
    EXPECT_TRUE(run("credit_card", "4111111111111112").empty());
    EXPECT_TRUE(run("credit_card", "order#A4111111111111111").empty());
    EXPECT_TRUE(run("credit_card", "41111111111111110000").empty());  // 20 digits
    EXPECT_TRUE(run("credit_card", "phone 0912345678").empty());
}

TEST(TwNationalId, Checksum) {
    EXPECT_TRUE(tw_national_id_valid("A123456789"));
    EXPECT_FALSE(tw_national_id_valid("A123456788"));
    EXPECT_FALSE(tw_national_id_valid("A323456789"));  // second digit must be 1/2/8/9
    EXPECT_FALSE(tw_national_id_valid("a123456789"));
}

TEST(TwNationalId, ScanRespectsWordBoundaries) {
    const auto m = run("tw_national_id", "身分證 A123456789 / XA123456789 / A1234567890");
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0].masked, "A*******89");
}

TEST(Tokens, AwsAndGithub) {
    auto aws = run("aws_access_key", "key=AKIAIOSFODNN7EXAMPLE;");
    ASSERT_EQ(aws.size(), 1u);
    EXPECT_EQ(aws[0].masked, "AKIA************MPLE");
    EXPECT_TRUE(run("aws_access_key", "AKIAshort").empty());

    auto gh = run("github_token", "token ghp_0123456789abcdefghijABCDEFGHIJ012345 end");
    ASSERT_EQ(gh.size(), 1u);
    EXPECT_TRUE(run("github_token", "ghp_tooshort").empty());
}

TEST(Email, BasicAndTrailingDot) {
    const auto m = run("email", "mail alice.w@example.com or bob@corp.example.tw. not a@b or x@y.c");
    ASSERT_EQ(m.size(), 2u);
    EXPECT_EQ(m[0].masked, "a******@example.com");
    EXPECT_EQ(m[1].masked, "b**@corp.example.tw");
}

TEST(Keyword, CaseInsensitiveAndUtf8) {
    auto d = make_keyword_detector("confidential", {"Confidential", "機密"});
    std::vector<Match> out;
    d->scan("CONFIDENTIAL draft — 機密文件 — confidential", out);
    EXPECT_EQ(out.size(), 3u);
}

TEST(Mask, ShortValuesFullyMasked) {
    EXPECT_EQ(mask("abc", 2, 2), "***");
    EXPECT_EQ(mask("abcdef", 1, 2), "a***ef");
}

TEST(Builtin, UnknownNameReturnsNull) { EXPECT_EQ(make_builtin_detector("nope"), nullptr); }

}  // namespace
}  // namespace dlp
