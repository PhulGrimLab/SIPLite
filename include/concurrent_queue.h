#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ConcurrentQueue 
{
public:
    ConcurrentQueue() = default;
    ~ConcurrentQueue() = default;

    // 복사/이동 금지
    ConcurrentQueue(const ConcurrentQueue&) = delete;
    ConcurrentQueue& operator=(const ConcurrentQueue&) = delete;
    ConcurrentQueue(ConcurrentQueue&&) = delete;
    ConcurrentQueue& operator=(ConcurrentQueue&&) = delete;

    void push(const T& value) 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(value);
        }
        cv_.notify_one();
    }

    // move 버전
    void push(T&& value) 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(value));
        }
        cv_.notify_one();
    }

    // 큐에서 요소를 꺼냄
    //  - 정상적으로 꺼내면 true
    //  - shutdown 이후 큐가 비어 있으면 false
    bool pop(T& out) 
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this]() 
        {
            return !queue_.empty() || shutdown_;
        });

        if (queue_.empty()) 
        {
            // shutdown + empty
            return false;
        }

        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // 워커 스레드 종료 알림
    void shutdown() 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (shutdown_) return;  // 이미 shutdown 됨
            shutdown_ = true;
        }
        cv_.notify_all();
    }

    bool empty() noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_ = false;
};
