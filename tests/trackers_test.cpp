#include <gtest/gtest.h>

#include "agent/content_scanner.h"
#include "agent/file_tracker.h"
#include "agent/network_tracker.h"
#include "agent/volume_map.h"

namespace dlp {
namespace {

TEST(FileTracker, ReportsOnlyWrittenFiles) {
    FileTracker t;
    t.on_create(0x1000, L"E:\\a.txt", 42);
    t.on_create(0x2000, L"E:\\b.txt", 42);
    t.on_write(0x1000, 100);
    t.on_write(0x1000, 50);
    t.on_write(0x9999, 10);  // untracked file object: ignored

    const auto a = t.on_cleanup(0x1000);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->path, L"E:\\a.txt");
    EXPECT_EQ(a->pid, 42u);
    EXPECT_EQ(a->bytes, 150u);

    EXPECT_FALSE(t.on_cleanup(0x2000).has_value());  // opened, never written
    EXPECT_EQ(t.tracked(), 0u);
}

TEST(FileTracker, ReusedFileObjectReplacesState) {
    FileTracker t;
    t.on_create(0x1000, L"E:\\old.txt", 1);
    t.on_write(0x1000, 10);
    t.on_create(0x1000, L"E:\\new.txt", 2);  // cleanup for old was lost
    EXPECT_FALSE(t.on_cleanup(0x1000).has_value());
}

TEST(FileTracker, CapsTrackedEntries) {
    FileTracker t(2);
    t.on_create(1, L"a", 1);
    t.on_create(2, L"b", 1);
    t.on_create(3, L"c", 1);
    EXPECT_EQ(t.tracked(), 2u);
    EXPECT_EQ(t.overflowed(), 1u);
}

TEST(NetworkTracker, ReportsOncePerWindow) {
    NetworkTracker n(1000, 60'000);
    EXPECT_FALSE(n.on_send(7, "1.2.3.4:443", 600, 0));
    EXPECT_EQ(n.on_send(7, "1.2.3.4:443", 600, 10), 1200u);
    EXPECT_FALSE(n.on_send(7, "1.2.3.4:443", 5000, 20));       // already reported
    EXPECT_FALSE(n.on_send(8, "1.2.3.4:443", 900, 20));        // separate process
    EXPECT_EQ(n.on_send(7, "1.2.3.4:443", 1000, 60'000), 1000u);  // new window
}

TEST(VolumeMap, ResolvesDevicePrefixes) {
    const std::vector<Volume> table{{L'C', L"\\Device\\HarddiskVolume1", false},
                                    {L'E', L"\\Device\\HarddiskVolume10", true}};
    auto r = VolumeMap::resolve_in(table, L"\\Device\\HarddiskVolume10\\dir\\x.txt");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->dos_path, L"E:\\dir\\x.txt");
    EXPECT_TRUE(r->removable);

    r = VolumeMap::resolve_in(table, L"\\device\\harddiskvolume1\\Windows");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->dos_path, L"C:\\Windows");
    EXPECT_FALSE(r->removable);

    EXPECT_FALSE(VolumeMap::resolve_in(table, L"\\Device\\HarddiskVolume11\\x").has_value());
    EXPECT_FALSE(VolumeMap::resolve_in(table, L"\\Device\\Mup\\server\\share").has_value());
}

TEST(DecodeText, Encodings) {
    EXPECT_EQ(decode_text("plain 4111"), "plain 4111");
    EXPECT_EQ(decode_text("\xEF\xBB\xBFwith bom"), "with bom");
    EXPECT_EQ(decode_text(std::string("\xFF\xFEh\0i\0", 6)), "hi");
    EXPECT_EQ(decode_text(std::string("\xFE\xFF\0h\0i", 6)), "hi");
    EXPECT_EQ(decode_text(std::string("a\0b\0c\0d\0", 8)), "abcd");  // BOM-less UTF-16LE
    EXPECT_FALSE(decode_text(std::string("PK\x03\x04\0\0\x14\0\x08\0", 10)).has_value());
}

}  // namespace
}  // namespace dlp
