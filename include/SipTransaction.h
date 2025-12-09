#pragma once

#include <string>
#include <chrono>
#include <functional>
#include <memory>

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

class SipTransaction 
{
public:
    SipTransaction(const TransactionKey& key, TransactionType type)
        : key_(key)
        , type_(type)
        , createdAt_(std::chrono::steady_clock::now())
        , lastActivity_(createdAt_)
        , retransmitCount_(0)
        , terminated_(false)
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
    bool isTerminated() const { return terminated_; }
    int retransmitCount() const { return retransmitCount_; }
    
    // 타이머 관련
    void updateActivity() 
    { 
        lastActivity_ = std::chrono::steady_clock::now(); 
    }
    
    std::chrono::milliseconds timeSinceCreation() const 
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - createdAt_);
    }
    
    std::chrono::milliseconds timeSinceLastActivity() const 
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastActivity_);
    }
    
    void incrementRetransmit() { ++retransmitCount_; }
    
    // 종료
    void terminate() { terminated_ = true; }

    // 원본 메시지 저장 (재전송용)
    void setOriginalMessage(const std::string& msg) { originalMessage_ = msg; }
    const std::string& originalMessage() const { return originalMessage_; }
    
    // 마지막 응답 저장
    void setLastResponse(const std::string& resp) { lastResponse_ = resp; }
    const std::string& lastResponse() const { return lastResponse_; }

    // 원격 주소
    void setRemoteAddr(const std::string& ip, uint16_t port) 
    { 
        remoteIp_ = ip; 
        remotePort_ = port; 
    }
    const std::string& remoteIp() const { return remoteIp_; }
    uint16_t remotePort() const { return remotePort_; }

protected:
    TransactionKey key_;
    TransactionType type_;
    std::chrono::steady_clock::time_point createdAt_;
    std::chrono::steady_clock::time_point lastActivity_;
    int retransmitCount_;
    bool terminated_;
    std::string originalMessage_;
    std::string lastResponse_;
    std::string remoteIp_;
    uint16_t remotePort_ = 0;
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
    
    ServerInviteState state() const { return state_; }
    
    void setState(ServerInviteState newState) 
    { 
        state_ = newState;
        updateActivity();
    }
    
    // 상태 전이 검증
    bool canTransitionTo(ServerInviteState newState) const 
    {
        switch (state_) 
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
    ServerInviteState state_;
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
    
    ServerNonInviteState state() const { return state_; }
    
    void setState(ServerNonInviteState newState) 
    { 
        state_ = newState;
        updateActivity();
    }

private:
    ServerNonInviteState state_;
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
    
    ClientInviteState state() const { return state_; }
    
    void setState(ClientInviteState newState) 
    { 
        state_ = newState;
        updateActivity();
    }
    
    int currentTimerA() const { return currentTimerA_; }
    void doubleTimerA() 
    { 
        currentTimerA_ = std::min(currentTimerA_ * 2, SipTimers::T2_MS); 
    }

private:
    ClientInviteState state_;
    int currentTimerA_;
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
    
    ClientNonInviteState state() const { return state_; }
    
    void setState(ClientNonInviteState newState) 
    { 
        state_ = newState;
        updateActivity();
    }
    
    int currentTimerE() const { return currentTimerE_; }
    void doubleTimerE() 
    { 
        currentTimerE_ = std::min(currentTimerE_ * 2, SipTimers::T2_MS); 
    }

private:
    ClientNonInviteState state_;
    int currentTimerE_;
};
