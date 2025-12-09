#pragma once

#include <string>
#include <chrono>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>

// ================================
// SIP 트랜잭션 상태 (RFC 3261)
// ================================

// 클라이언트 INVITE 트랜잭션 상태
enum class ClientInviteState 
{
    Calling,        // INVITE 전송, 응답 대기
    Proceeding,     // 1xx 수신
    Completed,      // 3xx-6xx 수신, ACK 전송
    Terminated      // 종료
};

// 클라이언트 Non-INVITE 트랜잭션 상태
enum class ClientNonInviteState 
{
    Trying,         // 요청 전송, 응답 대기
    Proceeding,     // 1xx 수신
    Completed,      // 최종 응답 수신
    Terminated      // 종료
};

// 서버 INVITE 트랜잭션 상태
enum class ServerInviteState 
{
    Proceeding,     // INVITE 수신, 1xx 전송
    Completed,      // 3xx-6xx 전송, ACK 대기
    Confirmed,      // ACK 수신 (2xx의 경우)
    Terminated      // 종료
};

// 서버 Non-INVITE 트랜잭션 상태
enum class ServerNonInviteState 
{
    Trying,         // 요청 수신, 처리 중
    Proceeding,     // 1xx 전송
    Completed,      // 최종 응답 전송
    Terminated      // 종료
};

// 트랜잭션 타입
enum class TransactionType 
{
    ClientInvite,
    ClientNonInvite,
    ServerInvite,
    ServerNonInvite
};

// ================================
// SIP 타이머 상수 (RFC 3261)
// ================================

namespace SipTimers 
{
    // T1: RTT 추정치 (500ms)
    constexpr int T1_MS = 500;
    
    // T2: 최대 재전송 간격 (4초)
    constexpr int T2_MS = 4000;
    
    // T4: 최대 메시지 지속 시간 (5초)
    constexpr int T4_MS = 5000;
    
    // Timer A: INVITE 재전송 초기 간격 (T1)
    constexpr int TIMER_A_MS = T1_MS;
    
    // Timer B: INVITE 트랜잭션 타임아웃 (64*T1 = 32초)
    constexpr int TIMER_B_MS = 64 * T1_MS;
    
    // Timer C: Proxy INVITE 트랜잭션 타임아웃 (>3분)
    constexpr int TIMER_C_MS = 180000;
    
    // Timer D: 응답 재전송 대기 (>32초 for UDP)
    constexpr int TIMER_D_MS = 32000;
    
    // Timer E: Non-INVITE 재전송 초기 간격 (T1)
    constexpr int TIMER_E_MS = T1_MS;
    
    // Timer F: Non-INVITE 트랜잭션 타임아웃 (64*T1)
    constexpr int TIMER_F_MS = 64 * T1_MS;
    
    // Timer G: INVITE 응답 재전송 간격 (T1)
    constexpr int TIMER_G_MS = T1_MS;
    
    // Timer H: ACK 수신 대기 (64*T1)
    constexpr int TIMER_H_MS = 64 * T1_MS;
    
    // Timer I: ACK 재전송 대기 (T4 for UDP)
    constexpr int TIMER_I_MS = T4_MS;
    
    // Timer J: Non-INVITE 요청 재전송 대기 (64*T1 for UDP)
    constexpr int TIMER_J_MS = 64 * T1_MS;
    
    // Timer K: 응답 재전송 대기 (T4 for UDP)
    constexpr int TIMER_K_MS = T4_MS;
    
    // 최대 재전송 횟수 (무한 재전송 방지)
    constexpr int MAX_RETRANSMIT_COUNT = 10;
    
    // 재전송 간격 계산 (오버플로우 방지)
    inline int calculateRetransmitInterval(int baseMs, int retransmitCount) 
    {
        // retransmitCount가 너무 크면 shift 오버플로우 방지
        if (retransmitCount >= 10) 
        {
            return T2_MS;  // 최대값으로 제한
        }
        int64_t interval = static_cast<int64_t>(baseMs) * (1 << retransmitCount);
        return static_cast<int>(std::min(interval, static_cast<int64_t>(T2_MS)));
    }
}

// ================================
// 트랜잭션 키 (Branch ID 기반)
// ================================

struct TransactionKey 
{
    std::string branch;     // Via 헤더의 branch 파라미터
    std::string method;     // CSeq의 메소드
    bool isServer;          // 서버/클라이언트 구분
    
    bool operator==(const TransactionKey& other) const 
    {
        return branch == other.branch && 
               method == other.method && 
               isServer == other.isServer;
    }
};

// TransactionKey 해시 함수
struct TransactionKeyHash 
{
    std::size_t operator()(const TransactionKey& key) const 
    {
        std::size_t h1 = std::hash<std::string>{}(key.branch);
        std::size_t h2 = std::hash<std::string>{}(key.method);
        std::size_t h3 = std::hash<bool>{}(key.isServer);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

// ================================
// SIP 트랜잭션 기본 클래스
// ================================
// 
// 뮤텍스 획득 순서 (데드락 방지):
//   1. activityMutex_ (시간 관련 데이터)
//   2. dataMutex_ (메시지/주소 데이터)
// 두 뮤텍스를 동시에 획득할 경우 반드시 위 순서를 지켜야 함
//

class SipTransaction 
{
public:
    SipTransaction(const TransactionKey& key, TransactionType type)
        : key_(key)
        , type_(type)
        , createdAt_(std::chrono::steady_clock::now())
        , lastActivity_(std::chrono::steady_clock::now())  // createdAt_에 의존하지 않고 직접 초기화
        , retransmitCount_(0)
        , terminated_(false)
        , remotePort_(0)
    {}
    
    virtual ~SipTransaction() = default;
    
    // 복사/이동 금지
    SipTransaction(const SipTransaction&) = delete;
    SipTransaction& operator=(const SipTransaction&) = delete;
    SipTransaction(SipTransaction&&) = delete;
    SipTransaction& operator=(SipTransaction&&) = delete;
    
    // 접근자
    const TransactionKey& key() const { return key_; }
    TransactionType type() const { return type_; }
    bool isTerminated() const { return terminated_.load(std::memory_order_acquire); }
    int retransmitCount() const { return retransmitCount_.load(std::memory_order_acquire); }
    
    // 타이머 관련
    void updateActivity() 
    { 
        std::lock_guard<std::mutex> lock(activityMutex_);
        lastActivity_ = std::chrono::steady_clock::now(); 
    }
    
    std::chrono::milliseconds timeSinceCreation() const 
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - createdAt_);
    }
    
    std::chrono::milliseconds timeSinceLastActivity() const 
    {
        std::lock_guard<std::mutex> lock(activityMutex_);
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastActivity_);
    }
    
    // 재전송 횟수 증가 (상한 검사 포함)
    bool incrementRetransmit() 
    { 
        int current = retransmitCount_.load(std::memory_order_acquire);
        while (current < SipTimers::MAX_RETRANSMIT_COUNT)
        {
            if (retransmitCount_.compare_exchange_weak(current, current + 1,
                std::memory_order_release, std::memory_order_acquire))
            {
                return true;
            }
        }
        return false;  // 상한 초과
    }
    
    // 종료
    void terminate() { terminated_.store(true, std::memory_order_release); }

    // 원본 메시지 저장 (재전송용)
    void setOriginalMessage(const std::string& msg) 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        originalMessage_ = msg; 
    }
    std::string originalMessage() const 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        return originalMessage_; 
    }
    
    // 마지막 응답 저장
    void setLastResponse(const std::string& resp) 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        lastResponse_ = resp; 
    }
    std::string lastResponse() const 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        return lastResponse_; 
    }

    // 원격 주소
    void setRemoteAddr(const std::string& ip, uint16_t port) 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        remoteIp_ = ip; 
        remotePort_ = port; 
    }
    std::string remoteIp() const 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        return remoteIp_; 
    }
    uint16_t remotePort() const 
    { 
        std::lock_guard<std::mutex> lock(dataMutex_);
        return remotePort_; 
    }

protected:
    TransactionKey key_;
    TransactionType type_;
    const std::chrono::steady_clock::time_point createdAt_;
    std::chrono::steady_clock::time_point lastActivity_;
    std::atomic<int> retransmitCount_;
    std::atomic<bool> terminated_;
    
    mutable std::mutex activityMutex_;
    mutable std::mutex dataMutex_;
    std::string originalMessage_;
    std::string lastResponse_;
    std::string remoteIp_;
    uint16_t remotePort_;
};

// ================================
// 서버 INVITE 트랜잭션
// ================================

class ServerInviteTransaction : public SipTransaction 
{
public:
    ServerInviteTransaction(const TransactionKey& key)
        : SipTransaction(key, TransactionType::ServerInvite)
        , state_(ServerInviteState::Proceeding)
    {}
    
    ServerInviteState state() const { return state_.load(std::memory_order_acquire); }
    
    // 상태 설정 (검증 포함)
    bool setState(ServerInviteState newState) 
    { 
        // 상태 전이 검증
        if (!canTransitionTo(newState))
        {
            return false;  // 잘못된 상태 전이
        }
        state_.store(newState, std::memory_order_release);
        updateActivity();
        return true;
    }
    
    // 검증 없이 강제 설정 (내부용)
    void forceState(ServerInviteState newState)
    {
        state_.store(newState, std::memory_order_release);
        updateActivity();
    }
    
    // 상태 전이 검증
    bool canTransitionTo(ServerInviteState newState) const 
    {
        ServerInviteState current = state_.load(std::memory_order_acquire);
        switch (current) 
        {
            case ServerInviteState::Proceeding:
                return newState == ServerInviteState::Completed ||
                       newState == ServerInviteState::Terminated;
            case ServerInviteState::Completed:
                return newState == ServerInviteState::Confirmed ||
                       newState == ServerInviteState::Terminated;
            case ServerInviteState::Confirmed:
                return newState == ServerInviteState::Terminated;
            case ServerInviteState::Terminated:
                return false;
        }
        return false;
    }

private:
    std::atomic<ServerInviteState> state_;
};

// ================================
// 서버 Non-INVITE 트랜잭션
// ================================

class ServerNonInviteTransaction : public SipTransaction 
{
public:
    ServerNonInviteTransaction(const TransactionKey& key)
        : SipTransaction(key, TransactionType::ServerNonInvite)
        , state_(ServerNonInviteState::Trying)
    {}
    
    ServerNonInviteState state() const { return state_.load(std::memory_order_acquire); }
    
    // 상태 설정 (검증 포함)
    bool setState(ServerNonInviteState newState) 
    { 
        // 상태 전이 검증
        ServerNonInviteState current = state_.load(std::memory_order_acquire);
        bool validTransition = false;
        
        switch (current)
        {
            case ServerNonInviteState::Trying:
                validTransition = (newState == ServerNonInviteState::Proceeding ||
                                   newState == ServerNonInviteState::Completed ||
                                   newState == ServerNonInviteState::Terminated);
                break;
            case ServerNonInviteState::Proceeding:
                validTransition = (newState == ServerNonInviteState::Completed ||
                                   newState == ServerNonInviteState::Terminated);
                break;
            case ServerNonInviteState::Completed:
                validTransition = (newState == ServerNonInviteState::Terminated);
                break;
            case ServerNonInviteState::Terminated:
                validTransition = false;
                break;
        }
        
        if (!validTransition) return false;
        
        state_.store(newState, std::memory_order_release);
        updateActivity();
        return true;
    }

private:
    std::atomic<ServerNonInviteState> state_;
};

// ================================
// 클라이언트 INVITE 트랜잭션
// ================================

class ClientInviteTransaction : public SipTransaction 
{
public:
    ClientInviteTransaction(const TransactionKey& key)
        : SipTransaction(key, TransactionType::ClientInvite)
        , state_(ClientInviteState::Calling)
        , currentTimerA_(SipTimers::TIMER_A_MS)
    {}
    
    ClientInviteState state() const { return state_.load(std::memory_order_acquire); }
    
    // 상태 설정 (검증 포함)
    bool setState(ClientInviteState newState) 
    { 
        if (!canTransitionTo(newState)) {
            return false;
        }
        state_.store(newState, std::memory_order_release);
        updateActivity();
        return true;
    }
    
    // 상태 전이 검증 (RFC 3261 Figure 5)
    bool canTransitionTo(ClientInviteState newState) const
    {
        ClientInviteState current = state_.load(std::memory_order_acquire);
        switch (current)
        {
            case ClientInviteState::Calling:
                return newState == ClientInviteState::Proceeding ||
                       newState == ClientInviteState::Completed ||
                       newState == ClientInviteState::Terminated;
            case ClientInviteState::Proceeding:
                return newState == ClientInviteState::Completed ||
                       newState == ClientInviteState::Terminated;
            case ClientInviteState::Completed:
                return newState == ClientInviteState::Terminated;
            case ClientInviteState::Terminated:
                return false;
        }
        return false;
    }
    
    int currentTimerA() const { return currentTimerA_.load(std::memory_order_acquire); }
    void doubleTimerA() 
    { 
        int current = currentTimerA_.load(std::memory_order_acquire);
        // 이미 최대값이면 불필요한 연산 방지
        if (current >= SipTimers::T2_MS) return;
        int doubled = std::min(current * 2, SipTimers::T2_MS);
        currentTimerA_.store(doubled, std::memory_order_release);
    }

private:
    std::atomic<ClientInviteState> state_;
    std::atomic<int> currentTimerA_;
};

// ================================
// 클라이언트 Non-INVITE 트랜잭션
// ================================

class ClientNonInviteTransaction : public SipTransaction 
{
public:
    ClientNonInviteTransaction(const TransactionKey& key)
        : SipTransaction(key, TransactionType::ClientNonInvite)
        , state_(ClientNonInviteState::Trying)
        , currentTimerE_(SipTimers::TIMER_E_MS)
    {}
    
    ClientNonInviteState state() const { return state_.load(std::memory_order_acquire); }
    
    // 상태 설정 (검증 포함)
    bool setState(ClientNonInviteState newState) 
    { 
        if (!canTransitionTo(newState)) {
            return false;
        }
        state_.store(newState, std::memory_order_release);
        updateActivity();
        return true;
    }
    
    // 상태 전이 검증 (RFC 3261 Figure 6)
    bool canTransitionTo(ClientNonInviteState newState) const
    {
        ClientNonInviteState current = state_.load(std::memory_order_acquire);
        switch (current)
        {
            case ClientNonInviteState::Trying:
                return newState == ClientNonInviteState::Proceeding ||
                       newState == ClientNonInviteState::Completed ||
                       newState == ClientNonInviteState::Terminated;
            case ClientNonInviteState::Proceeding:
                return newState == ClientNonInviteState::Completed ||
                       newState == ClientNonInviteState::Terminated;
            case ClientNonInviteState::Completed:
                return newState == ClientNonInviteState::Terminated;
            case ClientNonInviteState::Terminated:
                return false;
        }
        return false;
    }
    
    int currentTimerE() const { return currentTimerE_.load(std::memory_order_acquire); }
    void doubleTimerE() 
    { 
        int current = currentTimerE_.load(std::memory_order_acquire);
        // 이미 최대값이면 불필요한 연산 방지
        if (current >= SipTimers::T2_MS) return;
        int doubled = std::min(current * 2, SipTimers::T2_MS);
        currentTimerE_.store(doubled, std::memory_order_release);
    }

private:
    std::atomic<ClientNonInviteState> state_;
    std::atomic<int> currentTimerE_;
};
