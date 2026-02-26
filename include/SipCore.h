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
/*
단말이 주기적으로 서버에 보내는 SIP REGISTER 요청을 처리한 후에 서버가 저장하는 등록 정보 레코드.

이 Registration은 RFC3261에서 **Registrar(등록 서버)**가 유지하는 “Location binding(주소 바인딩)”의 최소 단위예요. 한마디로,

“이 사용자(AoR)에게 지금은 이 Contact로 보내면 된다”
를 저장해두는 레코드이다.

아래는 필드별 의미 + SIP 흐름에서 왜 필요한지 보충 설명이다.

---------------------------------------------
[aor (Address-of-Record)]

예: sip:1001@server-ip

**사용자/단말의 ‘논리 주소’**입니다.

“1001에게 전화 걸기/호출하기” = 결국 AoR을 대상으로 함.

Registrar는 AoR을 key로 해서 “현재 도달 가능한 주소(Contact)”들을 매핑합니다.

---------------------------------------------
[contact]

예: sip:1001@client-ip:port (또는 도메인/사설IP 포함 가능)

**실제 라우팅 목적지(현재 단말이 수신할 수 있다고 주장하는 주소)**입니다.

서버는 INVITE 같은 요청을 AoR로 받으면, Location Service에서 AoR → Contact를 찾아서 그 Contact로 프록시/전달합니다.

---------------------------------------------
[ip, port (실제 패킷 src 정보)]

“REGISTER를 보낸 UDP 패킷의 출발지 IP/포트”

이게 중요한 이유:

NAT 환경에서 Contact가 192.168.x.x 같은 사설 주소로 올 수 있고,

실제로는 “공인 NAT 매핑 주소(외부에서 보이는 src ip/port)”로 보내야 단말이 받습니다.

그래서 실무에서는 보통 contact만 믿지 않고,

received/rport(Via 기반) 또는 패킷 src를 함께 저장해서

NAT 트래버설용 실제 전달 주소로 활용합니다.

---------------------------------------------
[expiresAt]

“이 바인딩이 언제 만료되는지(절대 시각)”

REGISTER는 본질적으로 임대(lease) 개념이라, 서버는 만료를 관리해야 합니다.
*/
struct Registration
{
    std::string aor;        // "sip:1001@server-ip"
    std::string contact;    // "sip:1001@client-ip:port"
    std::string ip;         // 실제 패킷 src IP
    uint16_t    port = 0;   // 실제 패킷 src Port

    /* 만료시간 변수 설명 📅
    **std::chrono::steady_clock::time_point expiresAt;**는 지속적(모노토닉) 시계인 steady_clock 상의 특정 시점을 저장하는 변수입니다. 주로 타임아웃·만료 시각을 안전하게 표현할 때 씁니다.
    핵심 설명 🔧
    steady_clock는 시스템 시간이 바뀌어도(예: NTP 조정) 뒤로/앞으로 뛰지 않는 모노토닉(clock that never goes backwards) 타이머입니다.
    time_point는 시계의 "한 시점"을 나타내며, steady_clock::now()로 현재 시점을 얻고, 여기에 duration을 더해 만료 시점을 계산합니다.
    비교(예: 만료 여부)는 if (steady_clock::now() >= expiresAt)처럼 안전하게 할 수 있습니다.
    */
   /*
   **expiresAt**는 서버가 저장한 등록(Registration) 바인딩의 만료 시점(steady_clock 기준)을 저장합니다.
이 값이 현재 시점보다 이전이면 **해당 등록은 만료(삭제)**되어야 합니다.

    SIP 흐름에서의 역할 🔁
    클라이언트가 REGISTER를 보낼 때 Expires 헤더 또는 Contact의 expires 파라미터로 유효시간(TTL)을 지정합니다.
    서버는 이 TTL을 받아 만료 시각 = now + TTL로 계산해 expiresAt에 저장합니다.
    TTL이 0이면 즉시 삭제(unregister) 처리합니다.
    클라이언트가 갱신(다시 REGISTER)하면 expiresAt을 갱신(연장)합니다.
    서버 측 정리(주기적 스윕 또는 우선순위 큐 기반 스케줄러)가 expiresAt을 보고 만료된 항목을 제거합니다.
   * */

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
    /*
    SenderFn = SIP 텍스트(요청/응답) 전체 문자열을 지정된 IP:포트로 전송하는 콜백입니다(성공 여부를 bool로 반환). 
    1번째 인자 = 목적지 IP 문자열
    2번째 인자 = 목적지 UDP 포트
    3번째 인자 = 전송할 SIP 텍스트 전체(start-line + headers + \r\n + body)
    반환값 = 전송 성공 시 true, 실패 시 false

    SipCore는 내부에서 SIP 흐름 처리(예: INVITE 전달, provisional 응답, ACK, CANCEL 전달 등)를 수행한 뒤 네트워크로 내보낼 때 sender_(=SenderFn) 을 호출합니다.
    예: forward 된 INVITE, 100 Trying/180/200 응답, ACK, CANCEL, 487 등.
    실제 구현(워크스레드)에서는 UdpServer::start()가 SipCore::setSender(...)로 실제 UDP 전송 구현(sendTo)을 등록합니다.
    테스트에서는 setSender에 람다를 넣어 전송된 메시지를 캡처하여 검증합니다 (test_sipcore.cpp).

    정의(요약):
    using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&)>; — SipCore.h
    등록:
    sipCore_.setSender([this](const std::string& ip, uint16_t port, const std::string& data){ return this->sendTo(ip, port, data); }); — UdpServer::start()
    호출(예):
    sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg,100,"Trying")); — SipCore::handleInvite/handleResponse 등
    */
    using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&)>;
    /*
    코드 설명 
    std::function은 C++ 표준 라이브러리에서 제공하는 범용 함수 포인터 래퍼입니다.
    이를 통해 함수 포인터, 람다, 멤버 함수 포인터 등 다양한 호출 가능한 객체를 하나의 타입으로 다룰 수 있습니다.
    SipCore 클래스 내에서 SenderFn은 다음과 같은 역할을 합니다:
    1) 정의: using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&)>; 
       — SipCore.h
       SenderFn은 세 개의 매개변수를 받고 bool을 반환하는 함수 타입을 정의합니다.
       매개변수는 각각 목적지 IP 주소(문자열), 목적지 포트(16비트 정수), 전송할 SIP 메시지(문자열)입니다.
    2) 등록: sipCore_.setSender([this](const std::string& ip, uint16_t port, const std::string& data){ return this->sendTo(ip, port, data); }); 
       — UdpServer::start()
       UdpServer 클래스에서 SipCore의 setSender 메서드를 호출하여 실제 UDP 전송 구현을 등록합니다.
       여기서는 람다 함수를 사용하여 UdpServer의 sendTo 메서드를 호출하도록 합니다.
    3) 호출: sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg,100,"Trying")); 
       — SipCore::handleInvite/handleResponse 등
       SipCore 내부에서 SIP 흐름 처리 후 네트워크로 메시지를 전송할 때 sender_ 콜백을 호출합니다.
       예를 들어, INVITE 요청 전달, provisional 응답 전송 등에 사용됩니다.
    요약:
    SenderFn은 SipCore가 네트워크로 SIP 메시지를 전송할 때 사용하는 콜백 함수 타입을 정의하며, UdpServer에서 실제 전송 로직을 등록
    
    ┌─────────────┐     setSender()      ┌─────────────┐
    │  UdpServer  │ ─────────────────►   │   SipCore   │
    │             │   람다/함수 전달        │   sender_   │
    └─────────────┘                      └──────┬──────┘
                                                │
                                                │ sender_(ip, port, data)
                                                ▼
                                        UDP 패킷 전송
    */


    // 패킷 + 파싱된 SIP 메시지 → outResponse에 응답 생성

    /*
    
    ┌─────────────────────────────────────────────────────────────────────┐
    │  UdpServer::start()                                                 │
    │    │                                                                │
    │    ▼                                                                │
    │  sipCore_.setSender([this](...){ return this->sendTo(...); });      │
    │    │                                                                │
    │    ▼                                                                │
    │  SipCore::sender_ = 람다 함수 저장                                     │
    └─────────────────────────────────────────────────────────────────────┘
                                ⋮
                            (패킷 수신)
                                ⋮
    ┌─────────────────────────────────────────────────────────────────────┐
    │  SipCore::handleInvite() 등에서                                      │
    │    │                                                                │
    │    ▼                                                                │
    │  if (sender_) {                                                     │
    │      sender_(ip, port, data);  ─────────────────────┐               │
    │  }                                                  │               │
    └─────────────────────────────────────────────────────│───────────────┘
                                                          │
                                                          ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │  람다 실행: this->sendTo(ip, port, data)                              │
    │    │                                                                │
    │    ▼                                                                │
    │  UdpServer::sendTo() - 실제 UDP 패킷 전송                              │
    └─────────────────────────────────────────────────────────────────────┘
    */
    
    // 패킷 + 파싱된 SIP 메시지 → outResponse에 응답 생성
    bool handlePacket(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse);

    // Sender 설정 (UdpServer에서 설정)
    void setSender(SenderFn sender) { sender_ = std::move(sender); }

    // 응답 메시지 처리 (forwarded INVITE의 응답을 원래 호출자에게 전달)
    bool handleResponse(const UdpPacket& pkt, const SipMessage& msg);

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
        std::string remoteTarget;  // callee's Contact URI (for in-dialog request routing)
        std::chrono::steady_clock::time_point created;
    };

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
        // 올바른 뮤텍스 순서: callMutex_ → pendingInvMutex_ → dlgMutex_ (#7 fix)
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

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
                    std::string callId = it->first;

                    // Dialog 정리
                    dialogs_.erase(callId);

                    // PendingInvite 정리
                    for (auto pit = pendingInvites_.begin(); pit != pendingInvites_.end(); )
                    {
                        if (pit->first.rfind(callId + ":", 0) == 0)
                            pit = pendingInvites_.erase(pit);
                        else
                            ++pit;
                    }

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
        // 올바른 뮤텍스 순서: callMutex_ → pendingInvMutex_ → dlgMutex_ (#4 fix)
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto now = std::chrono::steady_clock::now();
        std::size_t removed = 0;

        for (auto it = pendingInvites_.begin(); it != pendingInvites_.end(); )
        {
            bool shouldRemove = false;

            if (it->second.state == TxState::COMPLETED)
            {
                if (it->second.expiry <= now)
                    shouldRemove = true;
            }
            else
            {
                if (now - it->second.ts > ttl)
                    shouldRemove = true;
            }

            if (shouldRemove)
            {
                // key에서 callId 추출 ("callId:cseqNum" 형식)
                std::string key = it->first;
                auto colonPos = key.find(':');
                if (colonPos != std::string::npos)
                {
                    std::string callId = key.substr(0, colonPos);
                    // 미확립 ActiveCall 및 Dialog도 함께 정리
                    auto acIt = activeCalls_.find(callId);
                    if (acIt != activeCalls_.end() && !acIt->second.confirmed)
                    {
                        activeCalls_.erase(acIt);
                    }
                    dialogs_.erase(callId);
                }

                it = pendingInvites_.erase(it);
                ++removed;
                continue;
            }
            ++it;
        }

        // 보류 CANCEL 목록도 정리 — 대응하는 INVITE가 오지 않은 stale 항목 제거
        // pendingCancels_는 pendingInvMutex_로 보호됨 (이미 잠금 상태)
        pendingCancels_.clear();

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

    // 프록시 Via 헤더 관리 (RFC 3261 §16.6/§16.7)
    std::string addProxyVia(const std::string& rawMsg) const;
    std::string removeTopVia(const std::string& rawMsg) const;

    // Record-Route 헤더 추가 (RFC 3261 §16.6 step 4)
    // 프록시가 INVITE를 전달할 때 Record-Route를 추가하여,
    // 이후 in-dialog 요청(ACK, BYE, re-INVITE)이 프록시를 경유하도록 보장
    std::string addRecordRoute(const std::string& rawMsg) const;

    // 자신을 가리키는 Route 헤더 제거 (loose routing, RFC 3261 §16.4)
    std::string stripOwnRoute(const std::string& rawMsg) const;

    // Request-URI 재작성 (RFC 3261 §16.6 step 6)
    // 프록시가 INVITE를 callee에게 전달할 때, Request-URI를 callee의 Contact 주소로 변경
    std::string rewriteRequestUri(const std::string& rawMsg, const std::string& newUri) const;

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
        std::string calleeIp;          // 수신자 IP (INVITE 전달 대상)
        uint16_t calleePort = 0;       // 수신자 Port
        std::string origRequest;       // 프록시 Via가 추가된 INVITE (callee에게 전달된 버전) — CANCEL/ACK 생성용
        std::string callerRequest;     // caller의 원본 INVITE (프록시 Via 없음) — 487 응답 생성용
        std::string lastResponse;      // last raw response forwarded back to caller
        TxState state = TxState::TRYING;
        int attempts = 0;              // retransmission attempts observed
        std::chrono::steady_clock::time_point ts;     // creation time
        std::chrono::steady_clock::time_point expiry; // when COMPLETED entry may be removed
    };

    mutable std::mutex pendingInvMutex_;
    std::unordered_map<std::string, PendingInvite> pendingInvites_;

    // CANCEL이 INVITE보다 먼저 처리될 때를 대비한 보류 CANCEL 저장소
    // key = callId:cseqNum (pendingInvites_와 동일한 키 형식)
    // pendingInvMutex_로 보호됨 (pendingInvites_와 동일한 뮤텍스)
    std::unordered_set<std::string> pendingCancels_;

    // Dialog storage
    mutable std::mutex dlgMutex_;
    std::unordered_map<std::string, Dialog> dialogs_;

    // Sender callback (set by UdpServer)
    SenderFn sender_;

    // 프록시 로컬 주소 정보 (Via 헤더 생성용)
    std::string localAddr_ = "127.0.0.1";
    uint16_t localPort_ = 5060;

public:
    // 프록시 로컬 주소 설정
    void setLocalAddress(const std::string& ip, uint16_t port)
    {
        localAddr_ = ip;
        localPort_ = port;
    }
};