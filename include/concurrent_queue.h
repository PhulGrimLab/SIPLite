#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ConcurrentQueue 
{
private:
    // 메모리를 따로 할당하지 않고 std::queue를 멤버로 사용
    // 이 변수들은 모두 **자동 저장 기간(Automatic Storage Duration)**을 가집니다.
    std::queue<T> queue_;           // 내부적으로 동적 할당 관리 RAII
    std::mutex mutex_;              // 스택/객체 내부에 직접 저장
    std::condition_variable cv_;    // 스택/객체 내부에 직접 저장
    bool shutdown_ = false;
    const std::size_t maxSize_;     // const로 변경 불가

public:
    // 최대 큐 크기 (메모리 보호)
    static constexpr std::size_t DEFAULT_MAX_SIZE = 10000;
    
    explicit ConcurrentQueue(std::size_t maxSize = DEFAULT_MAX_SIZE)
        : maxSize_(maxSize)
    {}
    
    ~ConcurrentQueue() = default;

    // 복사/이동 금지 Rule of Zero + Rule of Five의 혼합
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

    // move버전 (속도빠름, 원본이 필요없을때 유용)
    bool push(T&& value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (shutdown_ || queue_.size() >= maxSize_)
            {
                return false;
            }

            queue_.push(std::move(value)); // 이동 시도
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

        // 종료 상태에서 큐가 비어있으면 종료
        if (shutdown_ && queue_.empty())
        {
            return false;
        }
        
        // shutdown 상태라도 큐에 데이터가 있으면 처리
        if (queue_.empty())
        {
            return false;
        }

        // 큐에서 요소 하나 꺼내기
        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // 워커 스레드 종료 알림
    void shutdown() 
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (shutdown_)
            {
                return;
            }

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

};