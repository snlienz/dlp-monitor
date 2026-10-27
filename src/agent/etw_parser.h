#pragma once
#include <windows.h>

#include <evntcons.h>

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dlp {

// Decodes the top-level scalar properties of an event using its TDH schema.
//
// TdhGetEventInformation is expensive (it may consult the provider manifest), so the
// property layout is cached per (provider, event id, version). The user data is then
// walked directly, stopping at the first property whose size can't be known statically
// (structs, arrays, length-from-another-field); every DLP field we need sits before those.
//
// Views returned by str()/bin() point into the EVENT_RECORD and are only valid inside
// the callback that is handling it.
class EventParser {
public:
    bool parse(const EVENT_RECORD& record);

    std::optional<uint64_t> u64(std::wstring_view name) const;
    std::wstring_view str(std::wstring_view name) const;
    std::span<const unsigned char> bin(std::wstring_view name) const;

private:
    struct PropInfo {
        std::wstring name;
        USHORT in_type = 0;
        USHORT length = 0;
    };
    struct Key {
        GUID provider;
        USHORT id;
        UCHAR version;
        bool operator<(const Key& o) const;
    };
    struct Value {
        const PropInfo* info = nullptr;
        uint64_t num = 0;
        std::wstring_view str;
        std::span<const unsigned char> bin;
    };

    const std::vector<PropInfo>* layout_for(const EVENT_RECORD& record);
    const Value* find(std::wstring_view name) const;

    std::map<Key, std::vector<PropInfo>> cache_;
    std::vector<Value> values_;
    std::vector<unsigned char> info_buf_;
};

}  // namespace dlp
