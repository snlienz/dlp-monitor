#include <gtest/gtest.h>

#include "common/pipe_protocol.h"

namespace dlp::pipe {
namespace {

TEST(Frame, RoundTripAcrossSplitReads) {
    const std::string wire = encode_frame("hello") + encode_frame("") + encode_frame("world!");
    FrameDecoder dec;
    std::vector<std::string> got;
    // Feed one byte at a time to exercise partial headers and bodies.
    for (char c : wire) {
        dec.feed(&c, 1);
        while (auto m = dec.next()) got.push_back(*m);
    }
    ASSERT_EQ(got.size(), 3u);
    EXPECT_EQ(got[0], "hello");
    EXPECT_EQ(got[1], "");
    EXPECT_EQ(got[2], "world!");
    EXPECT_FALSE(dec.corrupt());
}

TEST(Frame, OversizedHeaderMarksCorrupt) {
    FrameDecoder dec;
    const char header[4] = {'\xff', '\xff', '\xff', '\x7f'};
    dec.feed(header, 4);
    EXPECT_FALSE(dec.next().has_value());
    EXPECT_TRUE(dec.corrupt());
}

TEST(Frame, EncodeRejectsTooLarge) {
    EXPECT_THROW(encode_frame(std::string(kMaxFrame + 1, 'x')), std::length_error);
}

}  // namespace
}  // namespace dlp::pipe
