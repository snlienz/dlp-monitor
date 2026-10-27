#include <gtest/gtest.h>

#include <thread>
#include <vector>

#include "common/bounded_queue.h"

namespace dlp {
namespace {

TEST(BoundedQueue, DropsWhenFull) {
    BoundedQueue<int> q(2);
    EXPECT_TRUE(q.try_push(1));
    EXPECT_TRUE(q.try_push(2));
    EXPECT_FALSE(q.try_push(3));
    EXPECT_EQ(q.dropped(), 1u);
    EXPECT_EQ(q.pop(), 1);
}

TEST(BoundedQueue, CloseDrainsThenStops) {
    BoundedQueue<int> q(4);
    q.try_push(1);
    q.close();
    EXPECT_FALSE(q.try_push(2));
    EXPECT_EQ(q.pop(), 1);
    EXPECT_EQ(q.pop(), std::nullopt);
}

TEST(BoundedQueue, ManyProducersManyConsumers) {
    BoundedQueue<int> q(1 << 16);
    constexpr int kPerProducer = 5000;
    std::atomic<long long> sum{0};
    std::atomic<int> popped{0};

    std::vector<std::thread> consumers;
    for (int i = 0; i < 3; ++i)
        consumers.emplace_back([&] {
            while (auto v = q.pop()) {
                sum += *v;
                ++popped;
            }
        });
    std::vector<std::thread> producers;
    for (int p = 0; p < 4; ++p)
        producers.emplace_back([&] {
            for (int i = 1; i <= kPerProducer; ++i) q.try_push(i);
        });
    for (auto& t : producers) t.join();
    q.close();
    for (auto& t : consumers) t.join();

    EXPECT_EQ(q.dropped(), 0u);
    EXPECT_EQ(popped.load(), 4 * kPerProducer);
    EXPECT_EQ(sum.load(), 4LL * kPerProducer * (kPerProducer + 1) / 2);
}

}  // namespace
}  // namespace dlp
