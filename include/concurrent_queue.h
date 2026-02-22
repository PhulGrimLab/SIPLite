#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>

template<typename T>
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

    // ConcurrentQueue 생성자
    // 단일 인자를 받는 생성자는 암시적 변환에 사용될 수 있으므로, 의도치 않은 변환을 막기 위해 explicit를 붙이는 것이 좋은 관행입니다.
    /**
     ConcurrentQueue<int> queue = 100;  // ❌ 컴파일 에러
     ConcurrentQueue<int> queue(100);   // ✅ 명시적 생성
     ConcurrentQueue<int> queue{100};   // ✅ 명시적 생성

     void process(ConcurrentQueue<int> q);
     process(500);  // ❌ 컴파일 에러
     process(ConcurrentQueue<int>(500));  // ✅ 명시적 생성
    */
    explicit ConcurrentQueue(std::size_t maxSize = DEFAULT_MAX_SIZE)
        : maxSize_(maxSize)
    {}

    /** ConcurrentQueue 소멸자 
     * 
        = default의 의미
        컴파일러에게 기본 소멸자를 자동 생성하도록 명시적으로 요청하는 것입니다.

        왜 사용하는가?
        이유	설명
        명시적 의도 표현	"이 클래스는 특별한 소멸 로직이 필요 없다"는 것을 명확히 문서화
        Rule of Zero/Five 준수	특수 멤버 함수에 대한 의도를 명시
        최적화	컴파일러가 trivial destructor로 인식하여 최적화 가능
        가독성	다른 개발자가 "소멸자를 의도적으로 기본값으로 둔 것"임을 알 수 있음
        작성 안 해도 되지 않나요?
        네, 작성하지 않아도 컴파일러가 자동으로 기본 소멸자를 생성합니다:
    */
    ~ConcurrentQueue() = default;

    // 복사/이동 금지 Rule of Zero + Rule of Five의 혼합
    ConcurrentQueue(const ConcurrentQueue&) = delete;
    ConcurrentQueue& operator=(const ConcurrentQueue&) = delete;
    ConcurrentQueue(ConcurrentQueue&&) = delete;
    ConcurrentQueue& operator=(ConcurrentQueue&&) = delete;

    // 큐에 요소 추가 (shutdown 상태이거나 가득 찾으면 false 반환)
    // lvalue버전 (복사, 속도느림, 원본이 필요할때 유용)
    bool push(const T& value)   // const 참조로 값을 받아 복사 비용 최소화
    {
        { // 임계 구역 시작, lock 범위
            std::lock_guard<std::mutex> lock(mutex_);

            // 종료 상태이거나 큐가 가득 찼으면 false 반환
            if (shutdown_ || queue_.size() >= maxSize_)
            {
                return false;
            }

            queue_.push(value); // 실제 큐에 값을 넣는다.

        }   // 임계 구역 끝, lock 해제

        // 대기 중인 스레드 하나를 깨운다. lock 해제 후 notify 하는 것이 좋다.
        // 락 해제 후 notify하면 spurious wakeup 감소 및 성능 향상
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

    // 큐에서 요소 하나를 꺼낸다. 큐가 비어있으면 대기.
    // 정상적으로 꺼내면 true, shutdown 상태이면 false 반환
    bool pop(T& out)
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // 큐가 비어있고 종료 상태가 아니면 대기
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

    // 워커스레드 종료 알림
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
        cv_.notify_all(); // 대기 중인 모든 스레드 깨우기
    }

    // shutdown 상태 초기화
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