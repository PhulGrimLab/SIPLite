#include "concurrent_queue.h"
#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <set>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

#define FAIL(reason) \
    do { std::cout << "FAILED: " << reason << "\n"; ++testsFailed; } while(0)

// ==============================================
// Section 1: 기본 생성 및 상수
// ==============================================

void test_default_max_size()
{
    TEST("DEFAULT_MAX_SIZE is 10000");
    assert(ConcurrentQueue<int>::DEFAULT_MAX_SIZE == 10000);
    PASS();
}

void test_default_construction()
{
    TEST("Default construction — empty, size 0");
    ConcurrentQueue<int> q;
    assert(q.empty());
    assert(q.size() == 0);
    PASS();
}

void test_custom_max_size_construction()
{
    TEST("Custom maxSize construction");
    ConcurrentQueue<int> q(5);
    assert(q.empty());
    assert(q.size() == 0);
    // maxSize=5 → 6번째 push는 실패해야 함
    for (int i = 0; i < 5; ++i)
        assert(q.push(i));
    assert(!q.push(999));
    assert(q.size() == 5);
    PASS();
}

// ==============================================
// Section 2: push 기본 동작
// ==============================================

void test_push_lvalue()
{
    TEST("push lvalue copy");
    ConcurrentQueue<std::string> q;
    std::string val = "hello";
    assert(q.push(val));
    assert(q.size() == 1);
    assert(!q.empty());
    // 원본은 변경되지 않아야 함 (복사)
    assert(val == "hello");
    PASS();
}

void test_push_rvalue()
{
    TEST("push rvalue move");
    ConcurrentQueue<std::string> q;
    std::string val = "world";
    assert(q.push(std::move(val)));
    assert(q.size() == 1);
    // move 후 val은 빈 상태 (보장은 아니지만 표준 구현에서 일반적)
    PASS();
}

void test_push_when_full()
{
    TEST("push returns false when full");
    ConcurrentQueue<int> q(3);
    assert(q.push(1));
    assert(q.push(2));
    assert(q.push(3));
    assert(q.size() == 3);
    assert(!q.push(4));
    assert(q.size() == 3);
    PASS();
}

void test_push_after_shutdown()
{
    TEST("push returns false after shutdown");
    ConcurrentQueue<int> q;
    q.shutdown();
    assert(!q.push(1));
    assert(q.empty());
    PASS();
}

// ==============================================
// Section 3: pop 기본 동작
// ==============================================

void test_pop_basic()
{
    TEST("pop drains queue in FIFO order");
    ConcurrentQueue<int> q;
    q.push(10);
    q.push(20);
    q.push(30);

    int out = 0;
    assert(q.pop(out));
    assert(out == 10);
    assert(q.pop(out));
    assert(out == 20);
    assert(q.pop(out));
    assert(out == 30);
    assert(q.empty());
    PASS();
}

void test_pop_after_shutdown_drains_remaining()
{
    TEST("pop after shutdown drains remaining items");
    ConcurrentQueue<int> q;
    q.push(1);
    q.push(2);
    q.push(3);
    q.shutdown();

    int out = 0;
    // shutdown 후에도 남은 데이터는 꺼낼 수 있어야 함
    assert(q.pop(out));
    assert(out == 1);
    assert(q.pop(out));
    assert(out == 2);
    assert(q.pop(out));
    assert(out == 3);
    // 이제 비어있으므로 false
    assert(!q.pop(out));
    PASS();
}

void test_pop_after_shutdown_empty_returns_false()
{
    TEST("pop after shutdown on empty queue returns false");
    ConcurrentQueue<int> q;
    q.shutdown();
    int out = 0;
    assert(!q.pop(out));
    PASS();
}

// ==============================================
// Section 4: shutdown
// ==============================================

void test_shutdown_basic()
{
    TEST("shutdown — double shutdown is safe");
    ConcurrentQueue<int> q;
    q.shutdown();
    q.shutdown(); // 두 번째 호출도 안전
    assert(!q.push(42));
    PASS();
}

void test_shutdown_unblocks_waiting_pop()
{
    TEST("shutdown unblocks waiting pop thread");
    ConcurrentQueue<int> q;
    std::atomic<bool> popReturned{false};
    std::atomic<bool> popResult{true};

    // pop은 빈 큐에서 블로킹되어야 하므로 별도 스레드에서 실행
    std::thread t([&]() {
        int out = 0;
        bool result = q.pop(out);
        popResult.store(result);
        popReturned.store(true);
    });

    // pop이 블로킹 상태에 들어갈 시간 확보
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(!popReturned.load()); // 아직 블로킹 중

    q.shutdown(); // 언블록

    t.join();
    assert(popReturned.load());
    assert(!popResult.load()); // 빈 큐에서 shutdown → false
    PASS();
}

// ==============================================
// Section 5: reset
// ==============================================

void test_reset_after_shutdown()
{
    TEST("reset clears shutdown and empties queue");
    ConcurrentQueue<int> q;
    q.push(1);
    q.push(2);
    q.shutdown();

    // push 실패 확인
    assert(!q.push(3));

    q.reset();

    // reset 후 다시 사용 가능
    assert(q.empty());
    assert(q.size() == 0);
    assert(q.push(10));
    assert(q.size() == 1);

    int out = 0;
    assert(q.pop(out));
    assert(out == 10);
    PASS();
}

void test_reset_without_shutdown()
{
    TEST("reset on active queue empties it");
    ConcurrentQueue<int> q;
    q.push(1);
    q.push(2);
    q.push(3);
    assert(q.size() == 3);

    q.reset();
    assert(q.empty());
    assert(q.size() == 0);
    assert(q.push(99));
    PASS();
}

// ==============================================
// Section 6: empty / size
// ==============================================

void test_empty_and_size()
{
    TEST("empty/size track push/pop correctly");
    ConcurrentQueue<int> q;
    assert(q.empty());
    assert(q.size() == 0);

    q.push(1);
    assert(!q.empty());
    assert(q.size() == 1);

    q.push(2);
    assert(q.size() == 2);

    int out;
    q.pop(out);
    assert(q.size() == 1);

    q.pop(out);
    assert(q.empty());
    assert(q.size() == 0);
    PASS();
}

// ==============================================
// Section 7: 멀티스레드 — Producer/Consumer
// ==============================================

void test_single_producer_single_consumer()
{
    TEST("Single producer, single consumer — 1000 items");
    ConcurrentQueue<int> q;
    const int COUNT = 1000;
    std::vector<int> received;
    received.reserve(COUNT);

    // Consumer thread
    std::thread consumer([&]() {
        for (int i = 0; i < COUNT; ++i) {
            int val;
            if (q.pop(val))
                received.push_back(val);
        }
    });

    // Producer (main thread)
    for (int i = 0; i < COUNT; ++i) {
        while (!q.push(i)) {
            std::this_thread::yield();
        }
    }

    consumer.join();

    assert(received.size() == static_cast<size_t>(COUNT));
    // FIFO 순서 검증
    for (int i = 0; i < COUNT; ++i) {
        assert(received[i] == i);
    }
    PASS();
}

void test_multiple_producers_single_consumer()
{
    TEST("4 producers, 1 consumer — 4000 items total");
    ConcurrentQueue<int> q;
    const int ITEMS_PER_PRODUCER = 1000;
    const int NUM_PRODUCERS = 4;
    std::atomic<int> totalProduced{0};
    std::vector<int> received;
    std::mutex recvMutex;

    // Consumer thread
    std::thread consumer([&]() {
        int expected = NUM_PRODUCERS * ITEMS_PER_PRODUCER;
        int count = 0;
        while (count < expected) {
            int val;
            if (q.pop(val)) {
                std::lock_guard<std::mutex> lock(recvMutex);
                received.push_back(val);
                ++count;
            }
        }
    });

    // Producer threads
    std::vector<std::thread> producers;
    for (int p = 0; p < NUM_PRODUCERS; ++p) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < ITEMS_PER_PRODUCER; ++i) {
                int value = p * ITEMS_PER_PRODUCER + i;
                while (!q.push(value)) {
                    std::this_thread::yield();
                }
                totalProduced.fetch_add(1);
            }
        });
    }

    for (auto& t : producers) t.join();
    consumer.join();

    assert(totalProduced.load() == NUM_PRODUCERS * ITEMS_PER_PRODUCER);
    assert(received.size() == static_cast<size_t>(NUM_PRODUCERS * ITEMS_PER_PRODUCER));

    // 모든 값이 도착했는지 확인 (순서는 보장 안 됨)
    std::set<int> receivedSet(received.begin(), received.end());
    assert(receivedSet.size() == static_cast<size_t>(NUM_PRODUCERS * ITEMS_PER_PRODUCER));
    PASS();
}

void test_producer_consumer_with_shutdown()
{
    TEST("Producer/consumer with mid-operation shutdown");
    ConcurrentQueue<int> q(100);
    std::atomic<int> consumed{0};
    std::atomic<bool> consumerDone{false};

    // Consumer — shutdown 될 때까지 계속 pop
    std::thread consumer([&]() {
        int val;
        while (q.pop(val)) {
            consumed.fetch_add(1);
        }
        consumerDone.store(true);
    });

    // Producer — 50개만 넣고 shutdown
    for (int i = 0; i < 50; ++i) {
        q.push(i);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    q.shutdown();

    consumer.join();
    assert(consumerDone.load());
    assert(consumed.load() == 50);
    PASS();
}

void test_multiple_consumers_shutdown()
{
    TEST("Multiple consumers unblocked by shutdown");
    ConcurrentQueue<int> q;
    const int NUM_CONSUMERS = 4;
    std::atomic<int> unblocked{0};

    std::vector<std::thread> consumers;
    for (int i = 0; i < NUM_CONSUMERS; ++i) {
        consumers.emplace_back([&]() {
            int val;
            q.pop(val); // 블로킹
            unblocked.fetch_add(1);
        });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    assert(unblocked.load() == 0); // 모두 블로킹 중

    q.shutdown();
    for (auto& t : consumers) t.join();
    assert(unblocked.load() == NUM_CONSUMERS); // 모두 언블록됨
    PASS();
}

// ==============================================
// Section 8: 스트레스 테스트
// ==============================================

void test_stress_high_throughput()
{
    TEST("Stress: 10000 items, 4 producers, 2 consumers");
    ConcurrentQueue<int> q(20000); // 충분한 크기
    const int ITEMS_PER_PRODUCER = 2500;
    const int NUM_PRODUCERS = 4;
    const int TOTAL = NUM_PRODUCERS * ITEMS_PER_PRODUCER;
    std::atomic<int> totalConsumed{0};

    // Consumers
    std::vector<std::thread> consumers;
    for (int c = 0; c < 2; ++c) {
        consumers.emplace_back([&]() {
            int val;
            while (totalConsumed.load() < TOTAL) {
                if (q.pop(val)) {
                    totalConsumed.fetch_add(1);
                }
            }
        });
    }

    // Producers
    std::vector<std::thread> producers;
    for (int p = 0; p < NUM_PRODUCERS; ++p) {
        producers.emplace_back([&, p]() {
            for (int i = 0; i < ITEMS_PER_PRODUCER; ++i) {
                while (!q.push(p * ITEMS_PER_PRODUCER + i)) {
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& t : producers) t.join();

    // 모든 producer 완료 후 남은 아이템 소진 대기
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (totalConsumed.load() < TOTAL &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    q.shutdown();
    for (auto& t : consumers) t.join();

    assert(totalConsumed.load() == TOTAL);
    PASS();
}

// ==============================================
// Section 9: 타입 호환성
// ==============================================

void test_queue_with_struct_type()
{
    TEST("Queue with struct type");
    struct Packet {
        std::string data;
        uint16_t port;
    };

    ConcurrentQueue<Packet> q;
    Packet p1{"hello", 5060};
    assert(q.push(p1));
    assert(q.push(Packet{"world", 5061}));
    assert(q.size() == 2);

    Packet out;
    assert(q.pop(out));
    assert(out.data == "hello");
    assert(out.port == 5060);
    assert(q.pop(out));
    assert(out.data == "world");
    assert(out.port == 5061);
    PASS();
}

void test_queue_maxsize_one()
{
    TEST("Queue with maxSize=1");
    ConcurrentQueue<int> q(1);
    assert(q.push(42));
    assert(!q.push(99)); // 가득 참

    int out;
    assert(q.pop(out));
    assert(out == 42);
    assert(q.push(100)); // 이제 공간 생김
    PASS();
}

// ==============================================
// main
// ==============================================

int main()
{
    std::cout << "=== ConcurrentQueue Tests ===\n\n";

    std::cout << "[Section 1] 기본 생성 및 상수\n";
    test_default_max_size();
    test_default_construction();
    test_custom_max_size_construction();

    std::cout << "\n[Section 2] push 기본 동작\n";
    test_push_lvalue();
    test_push_rvalue();
    test_push_when_full();
    test_push_after_shutdown();

    std::cout << "\n[Section 3] pop 기본 동작\n";
    test_pop_basic();
    test_pop_after_shutdown_drains_remaining();
    test_pop_after_shutdown_empty_returns_false();

    std::cout << "\n[Section 4] shutdown\n";
    test_shutdown_basic();
    test_shutdown_unblocks_waiting_pop();

    std::cout << "\n[Section 5] reset\n";
    test_reset_after_shutdown();
    test_reset_without_shutdown();

    std::cout << "\n[Section 6] empty / size\n";
    test_empty_and_size();

    std::cout << "\n[Section 7] 멀티스레드 Producer/Consumer\n";
    test_single_producer_single_consumer();
    test_multiple_producers_single_consumer();
    test_producer_consumer_with_shutdown();
    test_multiple_consumers_shutdown();

    std::cout << "\n[Section 8] 스트레스 테스트\n";
    test_stress_high_throughput();

    std::cout << "\n[Section 9] 타입 호환성\n";
    test_queue_with_struct_type();
    test_queue_maxsize_one();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
