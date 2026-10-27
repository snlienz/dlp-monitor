#include "agent/volume_map.h"

#include <windows.h>

#include <winioctl.h>

#include "common/handle.h"
#include "common/log.h"
#include "common/wstr.h"

namespace dlp {
namespace {

bool usb_bus(wchar_t letter) {
    const wchar_t path[] = {L'\\', L'\\', L'.', L'\\', letter, L':', L'\0'};
    // Zero access rights: enough for IOCTL_STORAGE_QUERY_PROPERTY and never blocks on media.
    UniqueHandle h(::CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                                 0, nullptr));
    if (!h) return false;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    alignas(STORAGE_DEVICE_DESCRIPTOR) unsigned char buf[1024]{};
    DWORD returned = 0;
    if (!::DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buf,
                           sizeof(buf), &returned, nullptr))
        return false;
    const auto bus = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf)->BusType;
    return bus == BusTypeUsb || bus == BusTypeSd || bus == BusTypeMmc || bus == BusType1394;
}

}  // namespace

VolumeMap::VolumeMap() : table_(std::make_shared<const std::vector<Volume>>()) {}

bool VolumeMap::refresh() {
    const auto old = table_.load();
    auto next = std::make_shared<std::vector<Volume>>();
    const DWORD mask = ::GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i))) continue;
        const wchar_t letter = static_cast<wchar_t>(L'A' + i);
        const wchar_t drive[] = {letter, L':', L'\0'};
        const wchar_t root[] = {letter, L':', L'\\', L'\0'};

        const UINT type = ::GetDriveTypeW(root);
        if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
        wchar_t device[MAX_PATH];
        if (!::QueryDosDeviceW(drive, device, MAX_PATH)) continue;

        Volume v{letter, device, type == DRIVE_REMOVABLE};
        // The bus-type probe opens the device; only do it for volumes we haven't seen.
        bool known = false;
        for (const auto& o : *old) {
            if (o.letter == letter && o.device == v.device) {
                v.removable = o.removable;
                known = true;
                break;
            }
        }
        if (!known && !v.removable) v.removable = usb_bus(letter);
        next->push_back(std::move(v));
    }

    const bool changed = next->size() != old->size() ||
                         !std::equal(next->begin(), next->end(), old->begin(), [](auto& a, auto& b) {
                             return a.letter == b.letter && a.device == b.device;
                         });
    if (changed) {
        for (const auto& v : *next)
            log::info("volume {}: {} {}", to_utf8(std::wstring(1, v.letter)), to_utf8(v.device),
                      v.removable ? "removable" : "fixed");
    }
    table_.store(std::move(next));
    return changed;
}

std::optional<ResolvedPath> VolumeMap::resolve(std::wstring_view nt_path) const {
    return resolve_in(*table_.load(), nt_path);
}

std::optional<ResolvedPath> VolumeMap::resolve_in(const std::vector<Volume>& table,
                                                  std::wstring_view nt_path) {
    for (const auto& v : table) {
        const size_t n = v.device.size();
        // Require a path separator after the device so Volume1 doesn't match Volume10.
        if (nt_path.size() > n && nt_path[n] == L'\\' &&
            ::_wcsnicmp(nt_path.data(), v.device.c_str(), n) == 0) {
            std::wstring dos{v.letter, L':'};
            dos.append(nt_path.substr(n));
            return ResolvedPath{std::move(dos), v.removable};
        }
    }
    return std::nullopt;
}

}  // namespace dlp
