#pragma once
#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace dlp {

struct Volume {
    wchar_t letter = 0;
    std::wstring device;  // e.g. \Device\HarddiskVolume5 (as returned by QueryDosDevice)
    bool removable = false;
};

struct ResolvedPath {
    std::wstring dos_path;  // E:\dir\file.txt
    bool removable = false;
};

// Translates the NT device paths ETW reports (\Device\HarddiskVolume5\x.txt) into DOS paths
// and knows which volumes are removable. "Removable" includes USB hard disks and card
// readers, which GetDriveType reports as DRIVE_FIXED, by asking the storage stack for the
// bus type.
//
// refresh() runs on a timer thread while resolve() runs on the ETW thread, so the table is
// published as an immutable snapshot through an atomic shared_ptr.
class VolumeMap {
public:
    VolumeMap();
    // Returns true when the set of volumes changed.
    bool refresh();
    std::optional<ResolvedPath> resolve(std::wstring_view nt_path) const;
    std::vector<Volume> volumes() const { return *table_.load(); }

    // Exposed for tests: matches `nt_path` against a fixed table.
    static std::optional<ResolvedPath> resolve_in(const std::vector<Volume>& table,
                                                  std::wstring_view nt_path);

private:
    std::atomic<std::shared_ptr<const std::vector<Volume>>> table_;
};

}  // namespace dlp
