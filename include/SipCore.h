#pragma once

#include "UdpPacket.h"
#include "Logger.h"

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
#include <cstdint>

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
    constexpr int TIMER_C_SEC = 180;                       // RFC 3261 §16.7 Timer C (3분)
    constexpr std::size_t MAX_SUBSCRIPTIONS = 10000;       // 최대 구독 개수
    constexpr int DEFAULT_SUB_EXPIRES_SEC = 3600;           // 기본 구독 유효 시간 (1시간)
    constexpr int MAX_SUB_EXPIRES_SEC = 7200;               // 최대 구독 유효 시간 (2시간)
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
    TransportType transport = TransportType::UDP;
    std::string authPassword; // REGISTER Digest 검증용 평문 비밀번호

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
    bool loggedIn = false;  // SIP REGISTER 메시지로 실제 로그인한 단말 여부
    bool isStatic = false;  // XML 설정으로 사전 등록된 단말 여부 (만료 시 삭제하지 않음)
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
    using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&, TransportType)>;
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
        TransportType callerTransport = TransportType::UDP;
        std::string calleeIp;
        uint16_t calleePort = 0;
        TransportType calleeTransport = TransportType::UDP;
        std::chrono::steady_clock::time_point startTime;
        bool confirmed = false;
        bool byeReceived = false;  // 첫 번째 BYE 수신 여부 (cross-BYE 처리용)
        std::string byeSenderIp;   // BYE를 보낸 쪽 IP
        uint16_t byeSenderPort = 0;
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
        TransportType callerTransport = TransportType::UDP;
        std::string calleeIp;
        uint16_t calleePort = 0;
        TransportType calleeTransport = TransportType::UDP;
        int cseq = 0;
        bool confirmed = false;  // true after ACK
        bool byeReceived = false;  // 첫 번째 BYE 수신 여부
        std::string byeSenderIp;
        uint16_t byeSenderPort = 0;
        std::string remoteTarget;  // callee's Contact URI (for in-dialog request routing)
        std::string callerContact; // caller's Contact URI (for BYE forwarding to caller)
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
                if (it->second.isStatic)
                {
                    // 정적 등록 단말은 삭제하지 않고 로그인 상태만 해제
                    it->second.loggedIn = false;
                    ++it;
                }
                else
                {
                    it = regs_.erase(it);
                    ++removed;
                }
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
            // BYE 수신 후 30초 경과한 통화도 정리
            bool shouldRemove = false;
            if (it->second.byeReceived)
            {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.startTime);
                shouldRemove = true;  // BYE 수신된 통화는 항상 정리 대상
                (void)elapsed;
            }
            else if (!it->second.confirmed)
            {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.startTime);
                if (elapsed > maxAge)
                {
                    shouldRemove = true;
                }
            }

            if (shouldRemove)
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

    // ================================
    // Timer C 만료 처리 (RFC 3261 §16.7)
    // INVITE 전달 후 180초 이내에 최종 응답을 수신하지 못하면
    // caller에게 408 Request Timeout을 보내고 callee에게 CANCEL을 전달한다.
    // 주기적으로 호출해야 함 (예: 메인 루프에서 1초 간격)
    // ================================
    std::size_t cleanupTimerC()
    {
        auto now = std::chrono::steady_clock::now();

        // 락 내에서 타임아웃 항목을 수집하고, 락 밖에서 네트워크 전송
        struct TimerCEntry {
            std::string key;
            std::string callerIp;
            uint16_t callerPort;
            TransportType callerTransport = TransportType::UDP;
            std::string calleeIp;
            uint16_t calleePort;
            TransportType calleeTransport = TransportType::UDP;
            std::string resp408;      // caller에게 보낼 408
            std::string cancelMsg;    // callee에게 보낼 CANCEL
            std::string callId;
        };
        std::vector<TimerCEntry> expired;

        {
            std::lock_guard<std::mutex> lockCall(callMutex_);
            std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
            std::lock_guard<std::mutex> lockDlg(dlgMutex_);

            for (auto it = pendingInvites_.begin(); it != pendingInvites_.end(); )
            {
                // COMPLETED 상태는 이미 최종 응답을 받은 것이므로 Timer C 대상이 아님
                if (it->second.state == TxState::COMPLETED)
                {
                    ++it;
                    continue;
                }

                if (it->second.timerCExpiry <= now)
                {
                    TimerCEntry entry;
                    entry.key = it->first;
                    entry.callerIp = it->second.callerIp;
                    entry.callerPort = it->second.callerPort;
                    entry.callerTransport = it->second.callerTransport;
                    entry.calleeIp = it->second.calleeIp;
                    entry.calleePort = it->second.calleePort;
                    entry.calleeTransport = it->second.calleeTransport;

                    // caller에게 보낼 408 — callerRequest(프록시 Via 없는 원본)로 생성
                    if (!it->second.callerRequest.empty())
                    {
                        SipMessage reqMsg;
                        if (parseSipMessage(it->second.callerRequest, reqMsg))
                        {
                            entry.resp408 = buildSimpleResponse(reqMsg, 408, "Request Timeout");
                        }
                    }

                    // callee에게 보낼 CANCEL
                    entry.cancelMsg = buildCancelForPending(it->second);

                    // callId 추출
                    auto colonPos = entry.key.find(':');
                    if (colonPos != std::string::npos)
                        entry.callId = entry.key.substr(0, colonPos);

                    expired.push_back(std::move(entry));

                    // 자료구조 정리
                    if (!expired.back().callId.empty())
                    {
                        auto acIt = activeCalls_.find(expired.back().callId);
                        if (acIt != activeCalls_.end() && !acIt->second.confirmed)
                        {
                            activeCalls_.erase(acIt);
                        }
                        dialogs_.erase(expired.back().callId);
                    }

                    it = pendingInvites_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        } // 락 해제

        // 락 밖에서 네트워크 전송
        for (const auto& e : expired)
        {
            if (sender_)
            {
                if (!e.resp408.empty())
                    sender_(e.callerIp, e.callerPort, e.resp408, e.callerTransport);
                if (!e.cancelMsg.empty())
                    sender_(e.calleeIp, e.calleePort, e.cancelMsg, e.calleeTransport);
            }
            Logger::instance().info("[Timer C] INVITE timeout: key=" + e.key
                + " → 408 to caller " + e.callerIp + ":" + std::to_string(e.callerPort)
                + ", CANCEL to callee " + e.calleeIp + ":" + std::to_string(e.calleePort));
        }

        return expired.size();
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
    // Subscription 구조체 (RFC 6665)
    // ================================
    struct Subscription
    {
        std::string subscriberAor;  // 구독자 AoR (From URI)
        std::string targetAor;      // 구독 대상 AoR (To URI / Request-URI)
        std::string event;          // Event 패키지 ("presence", "dialog", "message-summary" 등)
        std::string callId;         // SUBSCRIBE의 Call-ID (dialog 식별)
        std::string fromTag;        // SUBSCRIBE의 From tag
        std::string toTag;          // 서버가 생성한 To tag
        std::string subscriberIp;   // 구독자 IP
        uint16_t subscriberPort = 0;
        TransportType subscriberTransport = TransportType::UDP;
        std::string contact;        // 구독자 Contact URI
        int cseq = 0;               // 마지막 CSeq 번호 (NOTIFY 전송용)
        std::chrono::steady_clock::time_point expiresAt;
        enum class State { ACTIVE, PENDING, TERMINATED } state = State::PENDING;
    };

    // 활성 구독 수 조회
    std::size_t subscriptionCount() const
    {
        std::lock_guard<std::mutex> lock(subMutex_);
        return subscriptions_.size();
    }

    // ================================
    // 만료된 구독 정리 + NOTIFY(terminated) 발송
    // 주기적 호출 필요 (예: 메인 루프에서 1초 간격)
    // ================================
    std::size_t cleanupExpiredSubscriptions()
    {
        auto now = std::chrono::steady_clock::now();

        // 락 내에서 만료 항목 수집, 락 밖에서 네트워크 전송
        struct ExpiredSub {
            std::string key;
            std::string subscriberIp;
            uint16_t subscriberPort;
            TransportType subscriberTransport = TransportType::UDP;
            std::string notifyMsg;
        };
        std::vector<ExpiredSub> expired;

        {
            std::lock_guard<std::mutex> lock(subMutex_);
            for (auto it = subscriptions_.begin(); it != subscriptions_.end(); )
            {
                if (it->second.expiresAt <= now &&
                    it->second.state != Subscription::State::TERMINATED)
                {
                    ExpiredSub entry;
                    entry.key = it->first;
                    entry.subscriberIp = it->second.subscriberIp;
                    entry.subscriberPort = it->second.subscriberPort;
                    entry.subscriberTransport = it->second.subscriberTransport;
                    entry.notifyMsg = buildNotifyUnlocked_(it->first, "terminated;reason=timeout");
                    expired.push_back(std::move(entry));

                    it = subscriptions_.erase(it);
                }
                else if (it->second.state == Subscription::State::TERMINATED)
                {
                    it = subscriptions_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        for (const auto& e : expired)
        {
            if (sender_)
            {
                sender_(e.subscriberIp, e.subscriberPort, e.notifyMsg, e.subscriberTransport);
            }
            Logger::instance().info("[Subscription] Expired: key=" + e.key);
        }

        return expired.size();
    }

    // 특정 AoR을 구독 중인 구독자 목록 조회
    std::vector<Subscription> getSubscriptionsForTarget(const std::string& targetAor) const
    {
        std::vector<Subscription> result;
        std::lock_guard<std::mutex> lock(subMutex_);
        auto now = std::chrono::steady_clock::now();
        for (const auto& [key, sub] : subscriptions_)
        {
            if (extractUserFromUri(sub.targetAor) == extractUserFromUri(targetAor)
                && sub.state != Subscription::State::TERMINATED
                && sub.expiresAt > now)
            {
                result.push_back(sub);
            }
        }
        return result;
    }

    // 등록 상태 변경 시 구독자에게 NOTIFY 발송 (예: REGISTER 후 호출)
    void notifySubscribers(const std::string& aor, const std::string& body,
                           const std::string& contentType)
    {
        struct PendingNotify
        {
            std::string ip;
            uint16_t port = 0;
            std::string notify;
            TransportType transport = TransportType::UDP;
        };
        std::vector<PendingNotify> toSend;
        std::string user = extractUserFromUri(aor);

        {
            std::lock_guard<std::mutex> lock(subMutex_);
            auto now = std::chrono::steady_clock::now();
            for (auto& [key, sub] : subscriptions_)
            {
                if (extractUserFromUri(sub.targetAor) == user
                    && sub.state == Subscription::State::ACTIVE
                    && sub.expiresAt > now)
                {
                    PendingNotify entry;
                    entry.ip = sub.subscriberIp;
                    entry.port = sub.subscriberPort;
                    entry.transport = sub.subscriberTransport;
                    entry.notify = buildNotifyUnlocked_(key, "active", body, contentType);
                    toSend.push_back(std::move(entry));
                }
            }
        }

        if (sender_)
        {
            for (const auto& entry : toSend)
            {
                sender_(entry.ip, entry.port, entry.notify, entry.transport);
            }
        }
    }

    // ================================
    // 통계 정보 구조체 (한 번에 조회)
    // ================================

    struct ServerStats
    {
        std::size_t registrationCount = 0;          // 전체 등록된 사용자 수
        std::size_t activeRegistrationCount = 0;    // 만료되지 않은 활성 등록 수
        std::size_t loggedInCount = 0;              // 실제 SIP REGISTER로 로그인한 단말 수
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
                    if (reg.loggedIn)
                    {
                        ++stats.loggedInCount;
                    }
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
                          int expiresSec = SipConstants::DEFAULT_EXPIRES_SEC,
                          const std::string& authPassword = "",
                          TransportType transport = TransportType::UDP)
    {
        if (aor.empty())
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
        reg.transport = transport;
        reg.authPassword = authPassword;
        reg.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(expiresSec);
        reg.isStatic = true;  // XML 설정으로 등록된 단말

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
    // MESSAGE 처리 (RFC 3428)
    // ================================

    bool handleMessage(const UdpPacket& pkt,
                       const SipMessage& msg,
                       std::string& outResponse);

    // ================================
    // SUBSCRIBE 처리 (RFC 6665)
    // ================================

    bool handleSubscribe(const UdpPacket& pkt,
                         const SipMessage& msg,
                         std::string& outResponse);

    // ================================
    // NOTIFY 처리 (RFC 6665)
    // ================================

    bool handleNotify(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse);

    // NOTIFY 빌더 (구독자에게 상태 통지 전송)
    std::string buildNotify(const std::string& subKey,
                            const std::string& subState,
                            const std::string& body = "",
                            const std::string& contentType = "") const;

    // ================================
    // 헬퍼 함수들
    // ================================
    
    std::string extractTagFromHeader(const std::string& header) const; 
    
    std::string generateTag() const;

    // Max-Forwards 감소 (RFC 3261 §16.6 step 3)
    // 프록시가 요청을 전달할 때 Max-Forwards를 1 감소시키거나, 없으면 70으로 삽입
    std::string decrementMaxForwards(const std::string& rawMsg) const;

    // 프록시 Via 헤더 관리 (RFC 3261 §16.6/§16.7)
    std::string addProxyVia(const std::string& rawMsg,
                            TransportType transport = TransportType::UDP) const;
    std::string removeTopVia(const std::string& rawMsg) const;

    // Record-Route 헤더 추가 (RFC 3261 §16.6 step 4)
    // 프록시가 INVITE를 전달할 때 Record-Route를 추가하여,
    // 이후 in-dialog 요청(ACK, BYE, re-INVITE)이 프록시를 경유하도록 보장
    std::string addRecordRoute(const std::string& rawMsg,
                               TransportType transport = TransportType::UDP) const;

    // 자신을 가리키는 Route 헤더 제거 (loose routing, RFC 3261 §16.4)
    std::string stripOwnRoute(const std::string& rawMsg,
                              TransportType transport = TransportType::UDP) const;

    // Request-URI 재작성 (RFC 3261 §16.6 step 6)
    // 프록시가 INVITE를 callee에게 전달할 때, Request-URI를 callee의 Contact 주소로 변경
    std::string rewriteRequestUri(const std::string& rawMsg, const std::string& newUri) const;

    std::string buildInviteResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason,
                                    const std::string& toTag,
                                    const std::string& sdpBody,
                                    const std::string& contentType = "application/sdp",
                                    TransportType transport = TransportType::UDP);

    struct PendingInvite; // forward declaration

    std::string buildAckForPending(const PendingInvite& pi, const std::string& respRaw) const; 

    std::string buildCancelForPending(const PendingInvite& pi) const; 

    std::string buildSimpleResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason);

    std::string buildRegisterOk(const SipMessage& req);
    std::string buildRegisterAuthChallenge(const SipMessage& req,
                                           const std::string& nonce,
                                           bool stale);
    std::string buildLocalContactHeader(TransportType transport) const;
    enum class DialogPeerSide { Unknown, Caller, Callee };
    DialogPeerSide classifyDialogPeerSide(const ActiveCall& call,
                                          const SipMessage& msg,
                                          const UdpPacket& pkt) const;
    DialogPeerSide classifyDialogPeerSide(const Dialog& dlg,
                                          const ActiveCall* call,
                                          const SipMessage& msg,
                                          const UdpPacket& pkt) const;

private:
    struct DigestNonceState
    {
        std::chrono::steady_clock::time_point expiresAt;
        std::uint32_t lastNonceCount = 0;
    };

    mutable std::mutex regMutex_;
    std::map<std::string, Registration> regs_;
    mutable std::mutex authMutex_;
    std::unordered_map<std::string, DigestNonceState> registerNonces_;

    // AOR의 사용자 부분(user part)으로 regs_ 검색 (regMutex_ 홀드 상태에서 호출)
    std::map<std::string, Registration>::iterator findByUser_(const std::string& aor)
    {
        std::string user = extractUserFromUri(aor);
        if (user.empty()) return regs_.end();
        for (auto it = regs_.begin(); it != regs_.end(); ++it)
        {
            if (extractUserFromUri(it->first) == user)
                return it;
        }
        return regs_.end();
    }

    mutable std::mutex callMutex_;
    std::map<std::string, ActiveCall> activeCalls_;

    // Transaction state for INVITE
    enum class TxState { TRYING, PROCEEDING, COMPLETED };

    // Pending forwarded INVITEs: key = CallID:CSeq
    struct PendingInvite
    {
        std::string callerIp;
        uint16_t callerPort = 0;
        TransportType callerTransport = TransportType::UDP;
        std::string calleeIp;          // 수신자 IP (INVITE 전달 대상)
        uint16_t calleePort = 0;       // 수신자 Port
        TransportType calleeTransport = TransportType::UDP;
        std::string origRequest;       // 프록시 Via가 추가된 INVITE (callee에게 전달된 버전) — CANCEL/ACK 생성용
        std::string callerRequest;     // caller의 원본 INVITE (프록시 Via 없음) — 487 응답 생성용
        std::string callerContact;     // caller's Contact URI (from INVITE Contact header)
        std::string lastResponse;      // last raw response forwarded back to caller
        TxState state = TxState::TRYING;
        int attempts = 0;              // retransmission attempts observed
        std::chrono::steady_clock::time_point ts;     // creation time
        std::chrono::steady_clock::time_point expiry; // when COMPLETED entry may be removed
        std::chrono::steady_clock::time_point timerCExpiry; // RFC 3261 §16.7 Timer C
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

    // ================================
    // Subscription storage (RFC 6665)
    // ================================
    // key = callId

    mutable std::mutex subMutex_;
    std::unordered_map<std::string, Subscription> subscriptions_;  // key = callId

    // subMutex_ 이미 보유한 상태에서 호출 (deadlock 방지)
    std::string buildNotifyUnlocked_(const std::string& subKey,
                                      const std::string& subState,
                                      const std::string& body = "",
                                      const std::string& contentType = "") const;

    // Sender callback (set by UdpServer)
    SenderFn sender_;

    struct TransportLocalAddress
    {
        std::string ip = "127.0.0.1";
        uint16_t port = 5060;
    };

    // 프록시 로컬 주소 정보 (transport별 Via/Record-Route 생성용)
    TransportLocalAddress udpLocal_;
    TransportLocalAddress tcpLocal_;
    TransportLocalAddress tlsLocal_;

public:
    // 프록시 로컬 주소 설정
    void setLocalAddress(const std::string& ip, uint16_t port)
    {
        udpLocal_.ip = ip;
        udpLocal_.port = port;
        tcpLocal_.ip = ip;
        tcpLocal_.port = port;
        tlsLocal_.ip = ip;
        tlsLocal_.port = static_cast<uint16_t>(port + 1);
    }

    void setLocalAddressForTransport(TransportType transport,
                                     const std::string& ip,
                                     uint16_t port)
    {
        TransportLocalAddress* target = &udpLocal_;
        if (transport == TransportType::TCP)
        {
            target = &tcpLocal_;
        }
        else if (transport == TransportType::TLS)
        {
            target = &tlsLocal_;
        }

        if (!ip.empty() && ip != "0.0.0.0")
        {
            target->ip = ip;
        }
        target->port = port;
    }
};
