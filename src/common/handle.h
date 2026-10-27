#pragma once
#include <windows.h>

#include <utility>

namespace dlp {

// RAII owner for kernel HANDLEs. Treats both nullptr and INVALID_HANDLE_VALUE as empty
// because Win32 APIs disagree on which one signals failure.
class UniqueHandle {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : h_(std::exchange(other.h_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) reset(std::exchange(other.h_, nullptr));
        return *this;
    }

    HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }
    HANDLE release() noexcept { return std::exchange(h_, nullptr); }
    void reset(HANDLE h = nullptr) noexcept {
        if (*this) ::CloseHandle(h_);
        h_ = h;
    }

private:
    HANDLE h_ = nullptr;
};

}  // namespace dlp
