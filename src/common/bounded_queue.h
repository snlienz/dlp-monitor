#pragma once
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace dlp {

// Multi-producer / multi-consumer queue with a fixed capacity.
// Producers never block: try_push drops the item and counts it when full. This is the
// contract the ETW callback needs, since stalling ProcessTrace makes the kernel drop
// buffers for the whole session instead of just our backlog.
template <class T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity) : capacity_(capacity) {}

    bool try_push(T item) {
        {
            std::lock_guard lock(mu_);
            if (closed_ || items_.size() >= capacity_) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            items_.push_back(std::move(item));
        }
        cv_.notify_one();
        return true;
    }

    // Blocks until an item is available. Returns nullopt once closed and drained.
    std::optional<T> pop() {
        std::unique_lock lock(mu_);
        cv_.wait(lock, [&] { return closed_ || !items_.empty(); });
        if (items_.empty()) return std::nullopt;
        T item = std::move(items_.front());
        items_.pop_front();
        return item;
    }

    void close() {
        {
            std::lock_guard lock(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    size_t size() const {
        std::lock_guard lock(mu_);
        return items_.size();
    }
    size_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    const size_t capacity_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<T> items_;
    bool closed_ = false;
    std::atomic<size_t> dropped_{0};
};

}  // namespace dlp
