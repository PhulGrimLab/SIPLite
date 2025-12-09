#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ConcurrentQueue 
{
public:
    // 최대 큐 크기 (메모리 보호)
    static constexpr std::size_t DEFAULT_MAX_SIZE = 10000;
    
    explicit ConcurrentQueue(std::size_t maxSize = DEFAULT_MAX_SIZE)
        : maxSize_(maxSize)
    {}
    
    ~ConcurrentQueue() = default;

    // 복사/이동 금지
    ConcurrentQueue(const ConcurrentQueue&) = delete;
    ConcurrentQueue& operator=(const ConcurrentQueue&) = delete;
    ConcurrentQueue(ConcurrentQueue&&) = delete;
    ConcurrentQueue& operator=(ConcurrentQueue&&) = delete;

    // 큐에 요소 추가 (shutdown 상태이거나 가득 찼으면 false 반환)
    bool push(const T& value) 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (shutdown_ || queue_.size() >= maxSize_)
            {
                return false;
            }
            queue_.push(value);
        }
        cv_.notify_one();
        return true;
    }

    // move 버전
    bool push(T&& value) 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (shutdown_ || queue_.size() >= maxSize_)
            {
                return false;
            }
            queue_.push(std::move(value));
        }
        cv_.notify_one();
        return true;
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

        // shutdown 상태에서 큐가 비어있으면 종료
        if (shutdown_ && queue_.empty()) 
        {
            return false;
        }
        
        // shutdown 상태라도 큐에 데이터가 있으면 처리
        if (queue_.empty())
        {
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

    // shutdown 상태 리셋 및 큐 비우기 (재시작용)
    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = false;
        // 큐 비우기
        std::queue<T> empty;
        std::swap(queue_, empty);
    }

    bool empty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    std::size_t size()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_ = false;
    const std::size_t maxSize_;  // const로 변경 불가 보장
};
