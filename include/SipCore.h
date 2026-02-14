#pragma once

#include "UdpPacket.h"

#include <string>
#include <map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <vector>
#include <optional>
#include <thread>      // for std::this_thread::get_id()
#include <charconv>    // for std::from_chars
#include <limits>      // for std::numeric_limits

// ================================
// 0) 보안 상수 정의
// ================================

namespace SipConstants
{
    constexpr std::size_t MAX_MESSAGE_SIZE = 64 * 1024;    // 64KB 최대 메시지 크기
    constexpr std::size_t MAX_HEADER_SIZE = 8 * 1024;      // 8KB 최대 헤더 크기
    constexpr std::size_t MAX_BODY_SIZE = 64 * 1024;       // 64KB 최대 바디 크기
    constexpr std::size_t MAX_HEADERS_COUNT = 100;         // 최대 헤더 개수
    constexpr int MAX_EXPIRES_SEC = 7200;                  // 최대 등록 유효 시간 (2시간)
    constexpr int DEFAULT_EXPIRES_SEC = 3600;              // 기본 등록 유효 시간 (1시간)
    constexpr std::size_t MAX_REGISTRATIONS = 10000;       // 최대 등록 개수
    constexpr std::size_t MAX_ACTIVE_CALLS = 5000;         // 최대 활성 통화 개수
}

// ================================
// 1) 기본 타입 정의
// ================================

enum class SipType { Request, Response, Invalid };

struct SipMessage 
{
    // 명시적 생성자 / 소멸자
    SipMessage() = default;
    ~SipMessage() = default;
    
    SipMessage(const SipMessage&) = default;
    SipMessage& operator=(const SipMessage&) = default;
    SipMessage(SipMessage&&) = default;
    SipMessage& operator=(SipMessage&&) = default;

    SipType type = SipType::Invalid;                // 메시지 유형 - 기본은 Invalid

    // Request
    std::string method;                             // 요청 메서드
    std::string requestUri;                         // 요청 URI

    // Response
    int statusCode = 0;                             // 상태 코드
    std::string reasonPhrase;                       // 이유 구문

    // 공통 필드
    std::string sipVersion = "SIP/2.0";             // SIP 버전 - 기본은 SIP/2.0
    std::map<std::string, std::string> headers;     // 헤더 맵
    std::string body;                               // 메시지 바디    
};

// REGISTER 정보
struct Registration {
    std::string aor;        // "sip:1001@server-ip"
    std::string contact;    // "sip:1001@client-ip:port"
    std::string ip;         // 실제 패킷 src IP
    uint16_t    port = 0;   // 실제 패킷 src Port
    std::chrono::steady_clock::time_point expiresAt;
};

// ================================
// 2) 문자열 유틸
// ================================

#include "SipUtils.h"


// ================================
// 2-1) SIP 유효성 검사 함수
// ================================

// isValidSipMethod moved to SipUtils.h/src/SipUtils.cpp

// isValidSipVersion moved to SipUtils.h/src/SipUtils.cpp

// isValidStatusCode moved to SipUtils.h/src/SipUtils.cpp

// Request URI 기본 검증
// isValidRequestUri moved to SipUtils.h/src/SipUtils.cpp

// To 헤더에 tag 없으면 tag=server 추가
// ensureToTag moved to SipUtils.h/src/SipUtils.cpp

// ================================
// 3) SIP 파서
// ================================

#include "SipParser.h"

// ================================
// 4) SIP 코어 (REGISTER + INVITE 처리)
// ================================

#include <functional>
#include <unordered_map>
#include <chrono>

class SipCore 
{
public:
    using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&)>;

    // 패킷 + 파싱된 SIP 메시지 → outResponse에 응답 생성
    bool handlePacket(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse);

    // Sender 설정 (UdpServer에서 설정)
    void setSender(SenderFn sender) { sender_ = std::move(sender); }

    // 응답 메시지 처리 (forwarded INVITE의 응답을 원래 호출자에게 전달)
    bool handleResponse(const UdpPacket& pkt, const SipMessage& msg);

    // Registration 조회
    // WARNING: 반환된 포인터는 락 해제 후 무효화될 수 있음
    // 가능하면 findRegistrationSafe() 사용 권장
    [[deprecated("Use findRegistrationSafe() instead for thread safety")]]
    const Registration* findRegistration(const std::string& aor) const
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = regs_.find(aor);
        if (it != regs_.end())
        {
            return &it->second;
        }
        return nullptr;
    }

    // 활성 통화 정보
    struct ActiveCall
    {
        std::string callId;
        std::string fromUri;
        std::string toUri;
        std::string fromTag;
        std::string toTag;
        std::string callerIp;
        uint16_t callerPort = 0;
        std::string calleeIp;
        uint16_t calleePort = 0;
        std::chrono::steady_clock::time_point startTime;
        bool confirmed = false;
        // Store last SDP body and content-type seen for this call (pass-through)
        std::string lastSdp;
        std::string lastSdpContentType;
    };

    // Dialog state (minimal representation)
    struct Dialog
    {
        std::string callId;
        std::string callerTag;   // remote tag from caller (From tag)
        std::string calleeTag;   // remote tag from callee (To tag in 2xx)
        std::string callerIp;
        uint16_t callerPort = 0;
        std::string calleeIp;
        uint16_t calleePort = 0;
        int cseq = 0;
        bool confirmed = false;  // true after ACK
        std::chrono::steady_clock::time_point created;
    };

    // WARNING: 반환된 포인터는 락 해제 후 무효화될 수 있음
    // 가능하면 findCallSafe() 사용 권장
    [[deprecated("Use findCallSafe() instead for thread safety")]]
    const ActiveCall* findCall(const std::string& callId) const
    {
        std::lock_guard<std::mutex> lock(callMutex_);
        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            return &it->second;
        }
        return nullptr;
    }

    // ================================
    // 안전한 조회 함수 (복사본 반환)
    // ================================
    std::optional<Registration> findRegistrationSafe(const std::string& aor) const
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = regs_.find(aor);
        if (it != regs_.end())
        {
            return it->second;  // 복사본 반환
        }
        return std::nullopt;
    }

    std::optional<ActiveCall> findCallSafe(const std::string& callId) const
    {
        std::lock_guard<std::mutex> lock(callMutex_);
        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            return it->second;  // 복사본 반환
        }
        return std::nullopt;
    }

    // ================================
    // 만료된 등록 정보 정리 (주기적 호출 필요)
    // ================================
    
    std::size_t cleanupExpiredRegistrations()
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto now = std::chrono::steady_clock::now();
        std::size_t removed = 0;
        
        for (auto it = regs_.begin(); it != regs_.end(); )
        {
            if (it->second.expiresAt <= now)
            {
                it = regs_.erase(it);
                ++removed;
            }
            else
            {
                ++it;
            }
        }
        
        return removed;
    }

    // ================================
    // 오래된 미확립 통화 정리 (주기적 호출 필요)
    // ================================
    
    std::size_t cleanupStaleCalls(std::chrono::seconds maxAge = std::chrono::seconds(300))
    {
        std::lock_guard<std::mutex> lock(callMutex_);
        auto now = std::chrono::steady_clock::now();
        std::size_t removed = 0;
        
        for (auto it = activeCalls_.begin(); it != activeCalls_.end(); )
        {
            // 미확립 통화가 maxAge(기본 5분) 이상 경과하면 정리
            if (!it->second.confirmed)
            {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.startTime);
                if (elapsed > maxAge)
                {
                    it = activeCalls_.erase(it);
                    ++removed;
                    continue;
                }
            }
            ++it;
        }
        
        return removed;
    }

    // ================================
    // Pending INVITE (transaction) cleanup
    // ================================
    // Remove COMPLETED transactions whose expiry <= now, and remove
    // non-COMPLETED transactions older than `ttl`.
    std::size_t cleanupStaleTransactions(std::chrono::seconds ttl = std::chrono::seconds(32))
    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto now = std::chrono::steady_clock::now();
        std::size_t removed = 0;

        for (auto it = pendingInvites_.begin(); it != pendingInvites_.end(); )
        {
            if (it->second.state == TxState::COMPLETED)
            {
                if (it->second.expiry <= now)
                {
                    it = pendingInvites_.erase(it);
                    ++removed;
                    continue;
                }
            }
            else
            {
                if (now - it->second.ts > ttl)
                {
                    it = pendingInvites_.erase(it);
                    ++removed;
                    continue;
                }
            }
            ++it;
        }

        return removed;
    }

    // 등록된 사용자 수 조회
    std::size_t registrationCount() const
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        return regs_.size();
    }

    // 활성 통화 수 조회
    std::size_t activeCallCount() const
    {
        std::lock_guard<std::mutex> lock(callMutex_);
        return activeCalls_.size();
    }

    // ================================
    // 통계 정보 구조체 (한 번에 조회)
    // ================================

    struct ServerStats
    {
        std::size_t registrationCount = 0;          // 전체 등록된 사용자 수
        std::size_t activeRegistrationCount = 0;    // 만료되지 않은 활성 등록 수
        std::size_t activeCallCount = 0;            // 전체 활성 통화 수
        std::size_t confirmedCallCount = 0;         // ACK 받은 것만 카운트
        std::size_t pendingCallCount = 0;           // 미확립 통화 수
    };

    // 통계 정보 일괄 조회 (락 최소화)
    ServerStats getStats() const
    {
        ServerStats stats;
        const auto now = std::chrono::steady_clock::now();

        // 등록 통계
        {
            std::lock_guard<std::mutex> lock(regMutex_);
            stats.registrationCount = regs_.size();

            for (const auto& [aor, reg] : regs_)
            {
                if (reg.expiresAt > now)
                {
                    ++stats.activeRegistrationCount;
                    /*
                    C++ 권고 사항: 반환값을 쓰지 않으면 전위를 사용하는 것이 좋다.
                    */
                }
            }
        }

        // 통화 통계
        {
            std::lock_guard<std::mutex> lock(callMutex_);
            stats.activeCallCount = activeCalls_.size();

            for (const auto& [callId, call] : activeCalls_)
            {
                if (call.confirmed)
                {
                    ++stats.confirmedCallCount;
                }
                else
                {
                    ++stats.pendingCallCount;
                }
            }
        }

        return stats;
    }

    // ================================
    // 프로그래매틱 단말 등록 (XML 설정용)
    // ================================

    bool registerTerminal(const std::string& aor,
                          const std::string& contact,
                          const std::string& ip,
                          uint16_t port,
                          int expiresSec = SipConstants::DEFAULT_EXPIRES_SEC)
    {
        if (aor.empty() || ip.empty())
        {
            return false; // 필수 매개변수 누락
        }


        if (expiresSec < 0)
        {
            expiresSec = 0;
        }
        else if (expiresSec > SipConstants::MAX_EXPIRES_SEC)
        {
            expiresSec = SipConstants::MAX_EXPIRES_SEC;
        }

        Registration reg;
        reg.aor = aor;
        reg.contact = contact.empty() ? aor : contact;
        reg.ip = ip;
        reg.port = port;
        reg.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(expiresSec);

        {
            std::lock_guard<std::mutex> lock(regMutex_);

            if (regs_.find(aor) == regs_.end() && 
                regs_.size() >= SipConstants::MAX_REGISTRATIONS)
            {
                return false; // 최대 등록 수 초과
            }

            // reg값을 아래 라인 이후에는 사용하지 않기 때문에, std::move 가능
            regs_[aor] = std::move(reg);
        }

        return true;
    }
    
    // ================================
    // 등록 정보 조회 (콘솔 출력용, 필터링 옵션 포함)
    // ================================
    
    std::vector<Registration> getAllRegistrations(bool activeOnly = false) const
    {
        std::vector<Registration> result;
        std::lock_guard<std::mutex> lock(regMutex_);
        result.reserve(regs_.size());
        
        const auto now = std::chrono::steady_clock::now();
        
        for (const auto& [aor, reg] : regs_)
        {
            if (!activeOnly || reg.expiresAt > now)
            {
                result.push_back(reg);
            }
        }
        return result;
    }
    
    // ================================
    // 활성 통화 정보 조회 (콘솔 출력용, 필터링 옵션 포함)
    // ================================
    
    std::vector<ActiveCall> getAllActiveCalls(bool confirmedOnly = false) const
    {
        std::vector<ActiveCall> result;
        std::lock_guard<std::mutex> lock(callMutex_);
        result.reserve(activeCalls_.size());
        
        for (const auto& [callId, call] : activeCalls_)
        {
            if (!confirmedOnly || call.confirmed)
            {
                result.push_back(call);
            }
        }
        return result;
    }

private:
    bool handleRegister(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse);

    // ================================
    // INVITE 처리
    // ================================
    
    bool handleInvite(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse);

    // ================================
    // ACK 처리
    // ================================
    
    bool handleAck(const UdpPacket& pkt,
                   const SipMessage& msg,
                   std::string& outResponse);

    // ================================
    // BYE 처리
    // ================================
    
    bool handleBye(const UdpPacket& pkt,
                   const SipMessage& msg,
                   std::string& outResponse);

    // ================================
    // CANCEL 처리
    // ================================
    
    bool handleCancel(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse);

    // ================================
    // OPTIONS 처리
    // ================================
    
    bool handleOptions(const UdpPacket& pkt,
                       const SipMessage& msg,
                       std::string& outResponse);

    // ================================
    // 헬퍼 함수들
    // ================================
    
    std::string extractTagFromHeader(const std::string& header) const; 
    
    std::string generateTag() const; 

    std::string buildInviteResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason,
                                    const std::string& toTag,
                                    const std::string& sdpBody,
                                    const std::string& contentType = "application/sdp");

    struct PendingInvite; // forward declaration

    std::string buildAckForPending(const PendingInvite& pi, const std::string& respRaw) const; 

    std::string buildCancelForPending(const PendingInvite& pi) const; 

    std::string buildSimpleResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason);

    std::string buildRegisterOk(const SipMessage& req);

private:
    mutable std::mutex regMutex_;
    std::map<std::string, Registration> regs_;

    mutable std::mutex callMutex_;
    std::map<std::string, ActiveCall> activeCalls_;

    // Transaction state for INVITE
    enum class TxState { TRYING, PROCEEDING, COMPLETED };

    // Pending forwarded INVITEs: key = CallID:CSeq
    struct PendingInvite
    {
        std::string callerIp;
        uint16_t callerPort = 0;
        std::string origRequest;       // raw request forwarded
        std::string lastResponse;      // last raw response forwarded back to caller
        TxState state = TxState::TRYING;
        int attempts = 0;              // retransmission attempts observed
        std::chrono::steady_clock::time_point ts;     // creation time
        std::chrono::steady_clock::time_point expiry; // when COMPLETED entry may be removed
    };

    mutable std::mutex pendingInvMutex_;
    std::unordered_map<std::string, PendingInvite> pendingInvites_;

    // Dialog storage
    mutable std::mutex dlgMutex_;
    std::unordered_map<std::string, Dialog> dialogs_;

    // Sender callback (set by UdpServer)
    SenderFn sender_;
};
