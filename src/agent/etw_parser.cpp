#include "agent/etw_parser.h"

#include <tdh.h>

#include <cstring>

namespace dlp {

bool EventParser::Key::operator<(const Key& o) const {
    if (const int c = std::memcmp(&provider, &o.provider, sizeof(GUID)); c != 0) return c < 0;
    if (id != o.id) return id < o.id;
    return version < o.version;
}

const std::vector<EventParser::PropInfo>* EventParser::layout_for(const EVENT_RECORD& r) {
    const Key key{r.EventHeader.ProviderId, r.EventHeader.EventDescriptor.Id,
                  r.EventHeader.EventDescriptor.Version};
    if (auto it = cache_.find(key); it != cache_.end()) return &it->second;

    ULONG size = static_cast<ULONG>(info_buf_.size());
    ULONG err = ::TdhGetEventInformation(const_cast<EVENT_RECORD*>(&r), 0, nullptr,
                                         reinterpret_cast<TRACE_EVENT_INFO*>(info_buf_.data()), &size);
    if (err == ERROR_INSUFFICIENT_BUFFER) {
        info_buf_.resize(size);
        err = ::TdhGetEventInformation(const_cast<EVENT_RECORD*>(&r), 0, nullptr,
                                       reinterpret_cast<TRACE_EVENT_INFO*>(info_buf_.data()), &size);
    }
    // Cache failures as an empty layout so a schema-less event costs one lookup, not one per event.
    std::vector<PropInfo> layout;
    if (err == ERROR_SUCCESS) {
        const auto* info = reinterpret_cast<const TRACE_EVENT_INFO*>(info_buf_.data());
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
            const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
            const bool simple =
                !(p.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) && p.count <= 1;
            if (!simple) break;
            const auto* name =
                reinterpret_cast<const wchar_t*>(info_buf_.data() + p.NameOffset);
            layout.push_back({name, p.nonStructType.InType, p.length});
        }
    }
    return &cache_.emplace(key, std::move(layout)).first->second;
}

bool EventParser::parse(const EVENT_RECORD& r) {
    values_.clear();
    const auto* layout = layout_for(r);
    if (layout->empty()) return false;

    const auto* p = static_cast<const unsigned char*>(r.UserData);
    const auto* end = p + r.UserDataLength;
    const size_t ptr_size = (r.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;

    auto read_num = [&](size_t n, Value& v) {
        if (static_cast<size_t>(end - p) < n) return false;
        std::memcpy(&v.num, p, n);  // little-endian, zero-extended
        p += n;
        return true;
    };

    for (const auto& prop : *layout) {
        Value v{&prop};
        bool ok = true;
        switch (prop.in_type) {
            case TDH_INTYPE_INT8:
            case TDH_INTYPE_UINT8: ok = read_num(1, v); break;
            case TDH_INTYPE_INT16:
            case TDH_INTYPE_UINT16: ok = read_num(2, v); break;
            case TDH_INTYPE_INT32:
            case TDH_INTYPE_UINT32:
            case TDH_INTYPE_HEXINT32:
            case TDH_INTYPE_BOOLEAN:
            case TDH_INTYPE_FLOAT: ok = read_num(4, v); break;
            case TDH_INTYPE_INT64:
            case TDH_INTYPE_UINT64:
            case TDH_INTYPE_HEXINT64:
            case TDH_INTYPE_FILETIME:
            case TDH_INTYPE_DOUBLE: ok = read_num(8, v); break;
            case TDH_INTYPE_POINTER:
            case TDH_INTYPE_SIZET: ok = read_num(ptr_size, v); break;
            case TDH_INTYPE_GUID:
            case TDH_INTYPE_SYSTEMTIME:
            case TDH_INTYPE_BINARY: {
                const size_t n = prop.in_type == TDH_INTYPE_BINARY ? prop.length : 16;
                if (n == 0 || static_cast<size_t>(end - p) < n) {
                    ok = false;
                } else {
                    v.bin = {p, n};
                    p += n;
                }
                break;
            }
            case TDH_INTYPE_UNICODESTRING: {
                // Null-terminated; copy-free view over possibly unaligned data is fine on x64.
                const auto* s = reinterpret_cast<const wchar_t*>(p);
                const size_t max_chars = static_cast<size_t>(end - p) / sizeof(wchar_t);
                size_t n = 0;
                while (n < max_chars && s[n] != L'\0') ++n;
                v.str = {s, n};
                p += std::min(n + 1, max_chars) * sizeof(wchar_t);
                break;
            }
            case TDH_INTYPE_ANSISTRING: {
                const size_t max = static_cast<size_t>(end - p);
                size_t n = 0;
                while (n < max && p[n] != 0) ++n;
                v.bin = {p, n};
                p += std::min(n + 1, max);
                break;
            }
            case TDH_INTYPE_SID: {
                if (static_cast<size_t>(end - p) < 8) {
                    ok = false;
                    break;
                }
                const size_t sub = p[1];
                const size_t n = 8 + sub * 4;
                if (static_cast<size_t>(end - p) < n) {
                    ok = false;
                } else {
                    v.bin = {p, n};
                    p += n;
                }
                break;
            }
            default: ok = false; break;
        }
        if (!ok) break;
        values_.push_back(v);
    }
    return !values_.empty();
}

const EventParser::Value* EventParser::find(std::wstring_view name) const {
    for (const auto& v : values_)
        if (v.info->name == name) return &v;
    return nullptr;
}

std::optional<uint64_t> EventParser::u64(std::wstring_view name) const {
    const auto* v = find(name);
    if (!v || !v->str.empty() || !v->bin.empty()) return std::nullopt;
    return v->num;
}

std::wstring_view EventParser::str(std::wstring_view name) const {
    const auto* v = find(name);
    return v ? v->str : std::wstring_view{};
}

std::span<const unsigned char> EventParser::bin(std::wstring_view name) const {
    const auto* v = find(name);
    return v ? v->bin : std::span<const unsigned char>{};
}

}  // namespace dlp
