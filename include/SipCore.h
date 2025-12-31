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

struct SipMessage {
    // 명시적 생성자/소멸자
    SipMessage() = default;
    ~SipMessage() = default;
    SipMessage(const SipMessage&) = default;
    SipMessage& operator=(const SipMessage&) = default;
    SipMessage(SipMessage&&) = default;
    SipMessage& operator=(SipMessage&&) = default;

    SipType type = SipType::Invalid;

    // Request
    std::string method;
    std::string requestUri;

    // Response
    int statusCode = 0;
    std::string reasonPhrase;

    // 공통
    std::string sipVersion;
    std::map<std::string, std::string> headers; // key: 소문자 헤더 이름
    std::string body;
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

inline std::string ltrim(const std::string& s) 
{
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
    {
        ++i;
    }

    return s.substr(i);
}

inline std::string rtrim(const std::string& s) 
{
    if (s.empty())
    { 
        return s;
    }

    std::size_t i = s.size();
    while (i > 0 && std::isspace(static_cast<unsigned char>(s[i - 1])))
    {
        --i;
    }

    return s.substr(0, i);
}

inline std::string trim(const std::string& s) 
{
    return rtrim(ltrim(s));
}

inline std::string toLower(const std::string& s) 
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) 
    {
        out.push_back(static_cast<char>(std::tolower(c)));
    }

    return out;
}

// 헤더 값 조회 - 값으로 반환 (dangling reference 방지)
inline std::string getHeader(const SipMessage& msg, const std::string& name) 
{
    auto it = msg.headers.find(toLower(name));
    if (it == msg.headers.end()) 
    {
        return std::string{};
    }

    return it->second;
}

// 헤더 값에서 CRLF 제거 (Response Splitting 방지)
inline std::string sanitizeHeaderValue(const std::string& value)
{
    std::string result;
    result.reserve(value.size());
    
    for (char c : value)
    {
        // CR, LF, NULL 문자 제거
        if (c != '\r' && c != '\n' && c != '\0')
        {
            result += c;
        }
    }
    
    return result;
}

// "To: <sip:1001@server>;tag=..." 형태에서 URI 뽑기
inline std::string extractUriFromHeader(const std::string& headerValue)
{
    std::string v = headerValue;
    // angle bracket 안에 있으면 그걸 우선 사용
    auto lt = v.find('<');
    auto gt = v.find('>');

    if (lt != std::string::npos && gt != std::string::npos && gt > lt + 1) 
    {
        return trim(v.substr(lt + 1, gt - lt - 1));
    }

    // 그 외에는 ; 앞까지만 보고 그 안에서 "sip:" 찾기
    auto semi = v.find(';');
    if (semi != std::string::npos)
    {
        v = v.substr(0, semi);
    }

    v = trim(v);

    auto sipPos = v.find("sip:");
    if (sipPos != std::string::npos) 
    {
        return trim(v.substr(sipPos));
    }

    return std::string{};
}

// "sip:1002@server-ip" 에서 user 부분만 추출 (1002)
inline std::string extractUserFromUri(const std::string& uri) 
{
    std::string u = uri;
    auto sipPos = u.find("sip:");
    std::size_t start = (sipPos == std::string::npos) ? 0 : sipPos + 4;
    auto atPos = u.find('@', start);

    if (atPos == std::string::npos) 
    {
        return trim(u.substr(start));
    }

    return trim(u.substr(start, atPos - start));
}

// ================================
// 2-1) SIP 유효성 검사 함수
// ================================

inline bool isValidSipMethod(const std::string& method)
{
    static const std::unordered_set<std::string> validMethods = {
        "INVITE", "ACK", "BYE", "CANCEL", "REGISTER",
        "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY",
        "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"
    };
    return validMethods.find(method) != validMethods.end();
}

inline bool isValidSipVersion(const std::string& version)
{
    return version == "SIP/2.0";
}

inline bool isValidStatusCode(int code)
{
    return code >= 100 && code <= 699;
}

// Request URI 기본 검증
inline bool isValidRequestUri(const std::string& uri)
{
    // 빈 URI 거부
    if (uri.empty() || uri.size() > 256)
    {
        return false;
    }
    
    // sip: 또는 sips: 프리픽스 필수
    if (uri.substr(0, 4) != "sip:" && uri.substr(0, 5) != "sips:")
    {
        return false;
    }
    
    // 위험 문자 체크 (CRLF 인젝션)
    for (char c : uri)
    {
        if (c == '\r' || c == '\n' || c == '\0')
        {
            return false;
        }
    }
    
    return true;
}

// To 헤더에 tag 없으면 tag=server 추가
inline std::string ensureToTag(const std::string& to) 
{
    // 입력 정화 (CRLF 인젝션 방지)
    std::string sanitized = sanitizeHeaderValue(to);
    
    if (sanitized.find("tag=") != std::string::npos) 
    {
        return sanitized;
    }

    // 단순하게 뒤에 ;tag=server 붙이기
    if (!sanitized.empty() && sanitized.back() == '>') 
    {
        return sanitized + ";tag=server";
    }

    return sanitized + ";tag=server";
}

// ================================
// 3) SIP 파서
// ================================

// raw SIP 텍스트를 SipMessage로 파싱
inline bool parseSipMessage(const std::string& raw, SipMessage& out) noexcept
{
    try
    {
        out = SipMessage{};

        // 입력 크기 검증
        if (raw.empty() || raw.size() > SipConstants::MAX_MESSAGE_SIZE)
        {
            return false;
        }

        // 헤더/바디 분리
        std::size_t headerEnd = raw.find("\r\n\r\n");
        if (headerEnd == std::string::npos) 
        {
            return false;
        }

        // 헤더 크기 검증
        if (headerEnd > SipConstants::MAX_HEADER_SIZE)
        {
            return false;
        }

        std::string headerPart = raw.substr(0, headerEnd);
        std::string bodyPart   = raw.substr(headerEnd + 4);

        // 바디 크기 검증
        if (bodyPart.size() > SipConstants::MAX_BODY_SIZE)
        {
            return false;
        }

        // 첫 줄 (Request-Line 또는 Status-Line)
        std::size_t firstLineEnd = headerPart.find("\r\n");
        if (firstLineEnd == std::string::npos) 
        {
            return false;
        }

        std::string firstLine = headerPart.substr(0, firstLineEnd);
        firstLine = trim(firstLine);

        if (firstLine.empty())
        {
            return false;
        }

        // Response 인지 Request인지 판별
        if (firstLine.rfind("SIP/2.0", 0) == 0) 
        {
            // Response: "SIP/2.0 200 OK"
            std::istringstream iss(firstLine);
            std::string proto;
            iss >> proto >> out.statusCode;
            std::getline(iss, out.reasonPhrase);
            out.reasonPhrase = trim(out.reasonPhrase);
            out.sipVersion   = proto;
            out.type         = SipType::Response;

            // SIP 버전 검증
            if (!isValidSipVersion(out.sipVersion))
            {
                return false;
            }

            // 상태 코드 유효성 검증
            if (!isValidStatusCode(out.statusCode))
            {
                return false;
            }
        } 
        else 
        {
            // Request: "INVITE sip:1002@server SIP/2.0"
            std::istringstream iss(firstLine);
            iss >> out.method >> out.requestUri >> out.sipVersion;
            if (out.sipVersion.empty()) out.sipVersion = "SIP/2.0";
            out.type = SipType::Request;

            // 메소드 유효성 검증
            if (!isValidSipMethod(out.method))
            {
                return false;
            }

            // SIP 버전 검증
            if (!isValidSipVersion(out.sipVersion))
            {
                return false;
            }
            
            // Request URI 검증
            if (!isValidRequestUri(out.requestUri))
            {
                return false;
            }
        }

        // 헤더들 파싱
        std::size_t pos = firstLineEnd + 2;
        std::string lastHeaderName;
        std::size_t headerCount = 0;

        while (pos < headerPart.size()) 
        {
            // 헤더 개수 제한 검사
            if (headerCount >= SipConstants::MAX_HEADERS_COUNT)
            {
                return false;
            }

            std::size_t next = headerPart.find("\r\n", pos);
            std::string line;
            if (next == std::string::npos) 
            {
                line = headerPart.substr(pos);
                pos  = headerPart.size();
            } 
            else 
            {
                line = headerPart.substr(pos, next - pos);
                pos  = next + 2;
            }

            if (line.empty()) 
            {
                break; // 빈 줄이면 끝
            }

            // 헤더 지속 줄(공백으로 시작) 처리
            if ((line[0] == ' ' || line[0] == '\t') && !lastHeaderName.empty()) 
            {
                auto& hv = out.headers[lastHeaderName];
                hv += " ";
                hv += trim(line);
                continue;
            }

            std::size_t colon = line.find(':');
            if (colon == std::string::npos) 
            {
                continue;
            }

            std::string name  = toLower(trim(line.substr(0, colon)));
            std::string value = trim(line.substr(colon + 1));

            lastHeaderName = name;
            out.headers[name] = value;
            ++headerCount;
        }

        // 바디
        out.body = bodyPart;

        return true;
    }
    catch (const std::exception&)
    {
        // 파싱 중 예외 발생 시 안전하게 실패 처리
        out = SipMessage{};
        return false;
    }
}

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
                      std::string& outResponse)
    {
        outResponse.clear();

        if (msg.type != SipType::Request) 
        {
            return false;
        }

        std::string methodUpper = msg.method;
        std::transform(methodUpper.begin(), methodUpper.end(), 
                       methodUpper.begin(), ::toupper);

        if (methodUpper == "REGISTER") 
        {
            return handleRegister(pkt, msg, outResponse);
        }
        else if (methodUpper == "INVITE")
        {
            return handleInvite(pkt, msg, outResponse);
        }
        else if (methodUpper == "ACK")
        {
            return handleAck(pkt, msg, outResponse);
        }
        else if (methodUpper == "BYE")
        {
            return handleBye(pkt, msg, outResponse);
        }
        else if (methodUpper == "CANCEL")
        {
            return handleCancel(pkt, msg, outResponse);
        }
        else if (methodUpper == "OPTIONS")
        {
            return handleOptions(pkt, msg, outResponse);
        }

        // 지원하지 않는 메소드
        outResponse = buildSimpleResponse(msg, 501, "Not Implemented");
        return true;
    }

    // Sender 설정 (UdpServer에서 설정)
    void setSender(SenderFn sender) { sender_ = std::move(sender); }

    // 응답 메시지 처리 (forwarded INVITE의 응답을 원래 호출자에게 전달)
    bool handleResponse(const UdpPacket& pkt, const SipMessage& msg)
    {
        std::string callId = getHeader(msg, "call-id");
        std::string cseq  = getHeader(msg, "cseq");
        if (callId.empty() || cseq.empty())
            return false;

        // cseq는 일반적으로 "<num> METHOD"
        int cseqNum = 0;
        {
            size_t i = 0;
            while (i < cseq.size() && std::isspace((unsigned char)cseq[i])) ++i;
            while (i < cseq.size() && std::isdigit((unsigned char)cseq[i]))
            {
                cseqNum = cseqNum*10 + (cseq[i]-'0');
                ++i;
            }
        }

        std::string key = callId + ":" + std::to_string(cseqNum);

        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto it = pendingInvites_.find(key);
        if (it == pendingInvites_.end())
            return false;

        // Forward the response back to the original caller
        if (sender_)
        {
            sender_(it->second.callerIp, it->second.callerPort, pkt.data);
        }

        // Update transaction metadata
        if (msg.statusCode < 200)
        {
            it->second.state = TxState::PROCEEDING;
            it->second.lastResponse = pkt.data;
            it->second.attempts = 0;
        }
        else
        {
            // Final response
            it->second.state = TxState::COMPLETED;
            it->second.lastResponse = pkt.data;
            it->second.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(32);

            // If this is a 2xx response to INVITE, create minimal dialog entry
            if (msg.statusCode >= 200 && msg.statusCode < 300)
            {
                std::string cseq = getHeader(msg, "cseq");
                std::string method;
                // get method portion from cseq (e.g., "1 INVITE")
                {
                    size_t pos = 0;
                    while (pos < cseq.size() && std::isdigit((unsigned char)cseq[pos])) ++pos;
                    while (pos < cseq.size() && std::isspace((unsigned char)cseq[pos])) ++pos;
                    method = cseq.substr(pos);
                }
                std::string methodUpper = method;
                std::transform(methodUpper.begin(), methodUpper.end(), methodUpper.begin(), ::toupper);

                if (methodUpper.rfind("INVITE",0) == 0)
                {
                    // Build dialog from activeCalls and pending invite info
                    std::lock_guard<std::mutex> lock1(callMutex_);
                    std::lock_guard<std::mutex> lock2(pendingInvMutex_);

                    auto acIt = activeCalls_.find(callId);
                    if (acIt != activeCalls_.end())
                    {
                        Dialog dlg;
                        dlg.callId = callId;
                        dlg.callerTag = acIt->second.fromTag;
                        // extract callee tag from To header of response
                        std::string toHdr = getHeader(msg, "to");
                        dlg.calleeTag = extractTagFromHeader(toHdr);
                        dlg.callerIp = it->second.callerIp;
                        dlg.callerPort = it->second.callerPort;
                        dlg.calleeIp = pkt.remoteIp;
                        dlg.calleePort = pkt.remotePort;
                        // parse cseq number
                        int cseqNum = 0;
                        {
                            size_t i = 0;
                            while (i < cseq.size() && std::isspace((unsigned char)cseq[i])) ++i;
                            while (i < cseq.size() && std::isdigit((unsigned char)cseq[i]))
                            {
                                cseqNum = cseqNum*10 + (cseq[i]-'0');
                                ++i;
                            }
                        }
                        dlg.cseq = cseqNum;
                        dlg.created = std::chrono::steady_clock::now();
                        dlg.confirmed = false;

                        // If response has SDP, store it in ActiveCall for possible use
                        std::string body = msg.body;
                        std::string ctype = getHeader(msg, "content-type");
                        if (!body.empty())
                        {
                            acIt->second.lastSdp = body;
                            acIt->second.lastSdpContentType = ctype.empty() ? "application/sdp" : ctype;
                        }

                        std::lock_guard<std::mutex> lockd(dlgMutex_);
                        dialogs_[callId] = std::move(dlg);
                    }
                }

                // If dialog already confirmed and callee retransmits 2xx, send ACK to callee
                {
                    std::lock_guard<std::mutex> lockd(dlgMutex_);
                    auto dit = dialogs_.find(callId);
                    if (dit != dialogs_.end() && dit->second.confirmed)
                    {
                        // This may be a retransmitted 2xx; send ACK to callee to stop retransmission
                        // Build ACK from pending invite and last response
                        auto pit = pendingInvites_.find(key);
                        if (pit != pendingInvites_.end())
                        {
                            std::string ack = buildAckForPending(pit->second, pkt.data);
                            if (!ack.empty() && sender_)
                            {
                                sender_(pkt.remoteIp, pkt.remotePort, ack);
                            }
                        }
                    }
                }
            }
        }

        return true;
    }

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
        std::size_t registrationCount = 0;
        std::size_t activeRegistrationCount = 0;  // 만료되지 않은 것만
        std::size_t activeCallCount = 0;
        std::size_t confirmedCallCount = 0;
        std::size_t pendingCallCount = 0;
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
                          int expiresSec = 3600)
    {
        if (aor.empty() || ip.empty())
        {
            return false;
        }
        
        // Expires 범위 검증
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
        reg.expiresAt = std::chrono::steady_clock::now() + 
                        std::chrono::seconds(expiresSec);
        
        {
            std::lock_guard<std::mutex> lock(regMutex_);
            if (regs_.find(aor) == regs_.end() && 
                regs_.size() >= SipConstants::MAX_REGISTRATIONS)
            {
                return false;
            }
            regs_[aor] = reg;
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
                        std::string& outResponse)
    {
        // 필수 헤더들 (getHeader는 값을 반환하므로 직접 std::string으로 받음)
        std::string toHdr      = getHeader(msg, "to");
        std::string contactHdr = getHeader(msg, "contact");

        if (toHdr.empty() || contactHdr.empty()) 
        {
            // 잘못된 REGISTER
            outResponse = buildSimpleResponse(msg, 400, "Bad Request");
            return true;
        }

        // AOR
        std::string aor = extractUriFromHeader(toHdr);
        if (aor.empty())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request");
            return true;
        }

        // Expires (헤더 기준, 없으면 디폴트 3600sec)
        int expiresSec = SipConstants::DEFAULT_EXPIRES_SEC;
        std::string expHdr = getHeader(msg, "expires");
        if (!expHdr.empty()) 
        {
            // 숫자만 포함하는지 확인 (std::from_chars 사용으로 예외 없음)
            bool validNumber = !expHdr.empty() && expHdr.size() <= 10;
            for (char c : expHdr)
            {
                if (c < '0' || c > '9')
                {
                    validNumber = false;
                    break;
                }
            }
            
            if (validNumber)
            {
                int value = 0;
                auto [ptr, ec] = std::from_chars(
                    expHdr.data(), expHdr.data() + expHdr.size(), value);
                
                if (ec == std::errc{} && ptr == expHdr.data() + expHdr.size())
                {
                    // 범위 검증: 0 ~ MAX_EXPIRES_SEC
                    if (value < 0)
                    {
                        expiresSec = 0;
                    }
                    else if (value > SipConstants::MAX_EXPIRES_SEC)
                    {
                        expiresSec = SipConstants::MAX_EXPIRES_SEC;
                    }
                    else
                    {
                        expiresSec = value;
                    }
                }
            }
            // std::from_chars는 예외를 던지지 않으므로 catch 불필요
        }

        // Registration 저장
        Registration reg;
        reg.aor      = aor;
        reg.contact  = contactHdr;
        reg.ip       = pkt.remoteIp;
        reg.port     = pkt.remotePort;
        reg.expiresAt = std::chrono::steady_clock::now() +
                        std::chrono::seconds(expiresSec);

        {
            std::lock_guard<std::mutex> lock(regMutex_);
            // 기존 등록이 아닌 경우 개수 제한 검사
            auto it = regs_.find(aor);
            if (it == regs_.end() && regs_.size() >= SipConstants::MAX_REGISTRATIONS)
            {
                outResponse = buildSimpleResponse(msg, 503, "Service Unavailable");
                return true;
            }
            regs_[aor] = reg;
        }

        // 200 OK 생성
        outResponse = buildRegisterOk(msg);
        return true;
    }

    // ================================
    // INVITE 처리
    // ================================
    
    bool handleInvite(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse)
    {
        std::string toHdr     = getHeader(msg, "to");
        std::string fromHdr   = getHeader(msg, "from");
        std::string callId    = getHeader(msg, "call-id");
        std::string cseqHdr   = getHeader(msg, "cseq");
        // contactHdr는 향후 사용 예정
        // std::string contactHdr = getHeader(msg, "contact");

        if (toHdr.empty() || fromHdr.empty() || callId.empty() || cseqHdr.empty())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request");
            return true;
        }

        // 수신자 URI 추출
        std::string toUri = extractUriFromHeader(toHdr);
        std::string toUser = extractUserFromUri(toUri);
        (void)toUser;  // 향후 사용 예정

        // 등록된 사용자 찾기
        std::string targetAor = toUri;
        Registration regCopy;  // 포인터 대신 복사본 사용 (스레드 안전성)
        bool found = false;
        
        {
            std::lock_guard<std::mutex> lock(regMutex_);
            auto it = regs_.find(targetAor);
            if (it != regs_.end())
            {
                // 만료 시간 확인
                if (it->second.expiresAt > std::chrono::steady_clock::now())
                {
                    regCopy = it->second;  // 복사 후 락 해제
                    found = true;
                }
            }
        }

        if (!found)
        {
            // 사용자를 찾을 수 없음
            outResponse = buildSimpleResponse(msg, 404, "Not Found");
            return true;
        }

        // 즉시 100 Trying을 호출자에게 보냄
        if (sender_)
        {
            sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"));
        }
        else
        {
            // fall back: set outResponse to Trying so UdpServer can send it
            outResponse = buildSimpleResponse(msg, 100, "Trying");
        }

        // 활성 통화 등록
        std::string fromTag = extractTagFromHeader(fromHdr);
        std::string toTag = generateTag();  // 서버가 To-tag 생성

        {
            std::lock_guard<std::mutex> lock(callMutex_);
            // 기존 통화가 아닌 경우 개수 제한 검사
            auto existingIt = activeCalls_.find(callId);
            if (existingIt == activeCalls_.end() && activeCalls_.size() >= SipConstants::MAX_ACTIVE_CALLS)
            {
                outResponse = buildSimpleResponse(msg, 503, "Service Unavailable");
                return true;
            }
            ActiveCall call;
            call.callId = callId;
            call.fromUri = extractUriFromHeader(fromHdr);
            call.toUri = toUri;
            call.fromTag = fromTag;
            call.toTag = toTag;
            call.callerIp = pkt.remoteIp;
            call.callerPort = pkt.remotePort;
            call.calleeIp = regCopy.ip;
            call.calleePort = regCopy.port;
            call.startTime = std::chrono::steady_clock::now();
            call.confirmed = false;
            activeCalls_[callId] = call;
        }

        // Forward INVITE to callee (preserve raw request)
        // Key by Call-ID:CSeq-number to correlate responses
        int cseqNum = 0;
        {
            size_t i = 0;
            while (i < cseqHdr.size() && std::isspace((unsigned char)cseqHdr[i])) ++i;
            while (i < cseqHdr.size() && std::isdigit((unsigned char)cseqHdr[i]))
            {
                cseqNum = cseqNum*10 + (cseqHdr[i]-'0');
                ++i;
            }
        }

        std::string key = callId + ":" + std::to_string(cseqNum);

        // If existing transaction exists, treat as retransmission: resend lastResponse
        {
            std::lock_guard<std::mutex> lock(pendingInvMutex_);
            auto it = pendingInvites_.find(key);
            if (it != pendingInvites_.end())
            {
                // Retransmission from caller: resend lastResponse (or 100 Trying fallback)
                if (!it->second.lastResponse.empty() && sender_)
                {
                    sender_(pkt.remoteIp, pkt.remotePort, it->second.lastResponse);
                }
                else if (sender_)
                {
                    sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"));
                }
                // Do not create new tx
                return true;
            }
        }

        {
            std::lock_guard<std::mutex> lock(pendingInvMutex_);
            PendingInvite pi;
            pi.callerIp = pkt.remoteIp;
            pi.callerPort = pkt.remotePort;
            pi.origRequest = pkt.data;
            pi.ts = std::chrono::steady_clock::now();
            pi.state = TxState::TRYING;
            pi.lastResponse = buildSimpleResponse(msg, 100, "Trying");
            pendingInvites_[key] = std::move(pi);
        }

        if (sender_)
        {
            sender_(regCopy.ip, regCopy.port, pkt.data);
        }

        // 180 Ringing 응답 (기본 동작)
        outResponse = buildInviteResponse(msg, 180, "Ringing", activeCalls_[callId].toTag, "");

        return true;
    }

    // ================================
    // ACK 처리
    // ================================
    
    bool handleAck(const UdpPacket& pkt,
                   const SipMessage& msg,
                   std::string& outResponse)
    {
        std::string callId = getHeader(msg, "call-id");
        std::string cseqHdr = getHeader(msg, "cseq");

        if (callId.empty())
        {
            return false;
        }

        // Try to forward ACK to callee if we have an active call
        {
            std::lock_guard<std::mutex> lock(callMutex_);
            auto it = activeCalls_.find(callId);
            if (it != activeCalls_.end())
            {
                it->second.confirmed = true;
                if (sender_)
                {
                    // Forward raw ACK packet to callee
                    sender_(it->second.calleeIp, it->second.calleePort, pkt.data);
                }
            }
        }

        // Mark dialog confirmed if exists
        {
            std::lock_guard<std::mutex> lock(dlgMutex_);
            auto dit = dialogs_.find(callId);
            if (dit != dialogs_.end())
            {
                dit->second.confirmed = true;
            }
        }

        // Remove pending INVITE transaction (if exists) based on CallID:CSeq
        if (!cseqHdr.empty())
        {
            int cseqNum = 0;
            size_t i = 0;
            while (i < cseqHdr.size() && std::isspace((unsigned char)cseqHdr[i])) ++i;
            while (i < cseqHdr.size() && std::isdigit((unsigned char)cseqHdr[i]))
            {
                cseqNum = cseqNum*10 + (cseqHdr[i]-'0');
                ++i;
            }
            std::string key = callId + ":" + std::to_string(cseqNum);
            std::lock_guard<std::mutex> lock(pendingInvMutex_);
            pendingInvites_.erase(key);
        }

        // ACK에는 응답 없음
        outResponse.clear();
        return true;
    }

    // ================================
    // BYE 처리
    // ================================
    
    bool handleBye(const UdpPacket& pkt,
                   const SipMessage& msg,
                   std::string& outResponse)
    {
        (void)pkt;
        
        std::string callId = getHeader(msg, "call-id");
        
        if (callId.empty())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request");
            return true;
        }

        // 통화 종료
        {
            std::lock_guard<std::mutex> lock(callMutex_);
            auto it = activeCalls_.find(callId);
            if (it != activeCalls_.end())
            {
                activeCalls_.erase(it);
                outResponse = buildSimpleResponse(msg, 200, "OK");
                return true;
            }
        }

        // 통화를 찾을 수 없음
        outResponse = buildSimpleResponse(msg, 481, "Call/Transaction Does Not Exist");
        return true;
    }

    // ================================
    // CANCEL 처리
    // ================================
    
    bool handleCancel(const UdpPacket& pkt,
                      const SipMessage& msg,
                      std::string& outResponse)
    {
        (void)pkt;
        
        std::string callId = getHeader(msg, "call-id");
        std::string cseqHdr = getHeader(msg, "cseq");

        if (callId.empty() || cseqHdr.empty())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request");
            return true;
        }

        // Reply 200 OK for CANCEL to the caller
        outResponse = buildSimpleResponse(msg, 200, "OK");

        // Parse CSeq number
        int cseqNum = 0;
        size_t i = 0;
        while (i < cseqHdr.size() && std::isspace((unsigned char)cseqHdr[i])) ++i;
        while (i < cseqHdr.size() && std::isdigit((unsigned char)cseqHdr[i]))
        {
            cseqNum = cseqNum*10 + (cseqHdr[i]-'0');
            ++i;
        }

        std::string key = callId + ":" + std::to_string(cseqNum);

        // If there is a pending INVITE transaction, forward CANCEL to callee and
        // send 487 Request Terminated to the caller (and clean up)
        {
            std::lock_guard<std::mutex> lock(pendingInvMutex_);
            auto pit = pendingInvites_.find(key);
            if (pit != pendingInvites_.end())
            {
                // Find callee info from activeCalls
                std::string calleeIp;
                uint16_t calleePort = 0;
                {
                    std::lock_guard<std::mutex> lock2(callMutex_);
                    auto it = activeCalls_.find(callId);
                    if (it != activeCalls_.end())
                    {
                        calleeIp = it->second.calleeIp;
                        calleePort = it->second.calleePort;
                    }
                }

                // Forward CANCEL to callee if we have callee info
                std::string cancelRaw = buildCancelForPending(pit->second);
                if (!cancelRaw.empty() && !calleeIp.empty() && sender_)
                {
                    sender_(calleeIp, calleePort, cancelRaw);
                }

                // Send 487 Request Terminated to caller immediately to terminate the INVITE
                SipMessage pendingReq;
                if (parseSipMessage(pit->second.origRequest, pendingReq))
                {
                    std::string resp487 = buildSimpleResponse(pendingReq, 487, "Request Terminated");
                    if (sender_)
                    {
                        sender_(pit->second.callerIp, pit->second.callerPort, resp487);
                    }
                    pit->second.lastResponse = resp487;
                }

                // Mark as completed and set short expiry
                pit->second.state = TxState::COMPLETED;
                pit->second.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(8);

                // Remove active call record as it was not confirmed
                {
                    std::lock_guard<std::mutex> lock2(callMutex_);
                    auto it = activeCalls_.find(callId);
                    if (it != activeCalls_.end() && !it->second.confirmed)
                        activeCalls_.erase(it);
                }
            }
            else
            {
                // No matching INVITE transaction; nothing to forward, we already returned 200 OK
                std::lock_guard<std::mutex> lock2(callMutex_);
                auto it = activeCalls_.find(callId);
                if (it != activeCalls_.end() && !it->second.confirmed)
                {
                    activeCalls_.erase(it);
                }
            }
        }

        return true;
    }

    // ================================
    // OPTIONS 처리
    // ================================
    
    bool handleOptions(const UdpPacket& pkt,
                       const SipMessage& msg,
                       std::string& outResponse)
    {
        (void)pkt;
        
        std::ostringstream oss;
        oss << "SIP/2.0 200 OK\r\n";

        // 헤더 값 정화 (CRLF 인젝션 방지)
        std::string via     = sanitizeHeaderValue(getHeader(msg, "via"));
        std::string from    = sanitizeHeaderValue(getHeader(msg, "from"));
        std::string to      = sanitizeHeaderValue(getHeader(msg, "to"));
        std::string callId  = sanitizeHeaderValue(getHeader(msg, "call-id"));
        std::string cseq    = sanitizeHeaderValue(getHeader(msg, "cseq"));

        if (!via.empty())    oss << "Via: "     << via    << "\r\n";
        if (!from.empty())   oss << "From: "    << from   << "\r\n";
        if (!to.empty())     oss << "To: "      << ensureToTag(to) << "\r\n";
        if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
        if (!cseq.empty())   oss << "CSeq: "    << cseq   << "\r\n";

        oss << "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER\r\n";
        oss << "Accept: application/sdp\r\n";
        oss << "Server: SIPLite/0.1\r\n";
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";

        outResponse = oss.str();
        return true;
    }

    // ================================
    // 헬퍼 함수들
    // ================================
    
    std::string extractTagFromHeader(const std::string& header) const
    {
        // 입력 검증
        if (header.empty() || header.size() > SipConstants::MAX_HEADER_SIZE)
        {
            return "";
        }
        
        std::size_t tagPos = header.find("tag=");
        if (tagPos == std::string::npos) 
        {
            return "";
        }
        
        std::size_t start = tagPos + 4;
        if (start >= header.size())
        {
            return "";
        }
        
        std::size_t end = header.find_first_of(";,\r\n ", start);
        
        std::string tag;
        if (end == std::string::npos) 
        {
            tag = header.substr(start);
        }
        else
        {
            tag = header.substr(start, end - start);
        }
        
        // Tag 길이 검증
        if (tag.size() > 128)
        {
            return "";
        }
        
        return tag;
    }
    
    std::string generateTag() const
    {
        // 더 나은 시드 생성: 시간 + 스레드 ID 조합
        static thread_local std::mt19937 gen([]() -> std::mt19937::result_type {
            std::random_device rd;
            try {
                return static_cast<std::mt19937::result_type>(rd());
            } catch (...) {
                // random_device 실패 시 시간 기반 시드 사용
                auto seed = static_cast<std::mt19937::result_type>(
                    std::chrono::steady_clock::now().time_since_epoch().count() ^
                    std::hash<std::thread::id>{}(std::this_thread::get_id()));
                return seed;
            }
        }());
        // 범위를 명시적으로 지정 (0 ~ UINT32_MAX)
        static thread_local std::uniform_int_distribution<uint32_t> dis(
            0, std::numeric_limits<uint32_t>::max());
        
        std::ostringstream oss;
        oss << std::hex << dis(gen);
        return oss.str();
    }

    std::string buildInviteResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason,
                                    const std::string& toTag,
                                    const std::string& sdpBody,
                                    const std::string& contentType = "application/sdp")
    {
        std::ostringstream oss;
        oss << "SIP/2.0 " << code << " " << reason << "\r\n";

        // 헤더 값 정화 (CRLF 인젝션 방지)
        std::string via     = sanitizeHeaderValue(getHeader(req, "via"));
        std::string from    = sanitizeHeaderValue(getHeader(req, "from"));
        std::string to      = sanitizeHeaderValue(getHeader(req, "to"));
        std::string callId  = sanitizeHeaderValue(getHeader(req, "call-id"));
        std::string cseq    = sanitizeHeaderValue(getHeader(req, "cseq"));

        if (!via.empty())    oss << "Via: "     << via    << "\r\n";
        if (!from.empty())   oss << "From: "    << from   << "\r\n";
        
        // To 헤더에 tag 추가
        if (!to.empty())
        {
            std::string toWithTag = to;
            if (to.find("tag=") == std::string::npos && !toTag.empty())
            {
                if (!to.empty() && to.back() == '>')
                {
                    toWithTag = to + ";tag=" + toTag;
                }
                else
                {
                    toWithTag = to + ";tag=" + toTag;
                }
            }
            oss << "To: " << toWithTag << "\r\n";
        }
        
        if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
        if (!cseq.empty())   oss << "CSeq: "    << cseq   << "\r\n";

        // Contact 헤더 (2xx 응답에 필요)
        if (code >= 200 && code < 300)
        {
            oss << "Contact: <sip:server@0.0.0.0:5060>\r\n";
        }

        oss << "Server: SIPLite/0.1\r\n";

        if (!sdpBody.empty())
        {
            // Use provided content type
            oss << "Content-Type: " << contentType << "\r\n";
            oss << "Content-Length: " << sdpBody.size() << "\r\n";
            oss << "\r\n";
            oss << sdpBody;
        }
        else
        {
            oss << "Content-Length: 0\r\n";
            oss << "\r\n";
        }

        return oss.str();
    }

    struct PendingInvite; // forward declaration

    std::string buildAckForPending(const PendingInvite& pi, const std::string& respRaw) const
    {
        SipMessage req, resp;
        if (!parseSipMessage(pi.origRequest, req))
            return std::string();
        if (!parseSipMessage(respRaw, resp))
            return std::string();

        std::string requestUri = req.requestUri;
        if (!isValidRequestUri(requestUri))
            requestUri = "sip:unknown";

        std::string fromHdr = sanitizeHeaderValue(getHeader(req, "from"));
        std::string toHdr = getHeader(resp, "to");
        std::string callId = sanitizeHeaderValue(getHeader(resp, "call-id"));
        std::string cseq = getHeader(resp, "cseq");

        int cseqNum = 0;
        size_t i = 0;
        while (i < cseq.size() && std::isspace((unsigned char)cseq[i])) ++i;
        while (i < cseq.size() && std::isdigit((unsigned char)cseq[i]))
        {
            cseqNum = cseqNum*10 + (cseq[i]-'0');
            ++i;
        }

        std::ostringstream oss;
        oss << "ACK " << requestUri << " SIP/2.0\r\n";

        std::string via = sanitizeHeaderValue(getHeader(resp, "via"));
        if (!via.empty()) oss << "Via: " << via << "\r\n";

        if (!fromHdr.empty()) oss << "From: " << fromHdr << "\r\n";
        if (!toHdr.empty())   oss << "To: " << toHdr << "\r\n";
        if (!callId.empty())  oss << "Call-ID: " << callId << "\r\n";

        oss << "CSeq: " << cseqNum << " ACK\r\n";
        oss << "Content-Length: 0\r\n\r\n";

        return oss.str();
    }

    std::string buildCancelForPending(const PendingInvite& pi) const
    {
        SipMessage req;
        if (!parseSipMessage(pi.origRequest, req))
            return std::string();

        std::string requestUri = req.requestUri;
        if (!isValidRequestUri(requestUri))
            requestUri = "sip:unknown";

        std::string via = sanitizeHeaderValue(getHeader(req, "via"));
        std::string from = sanitizeHeaderValue(getHeader(req, "from"));
        std::string to = sanitizeHeaderValue(getHeader(req, "to"));
        std::string callId = sanitizeHeaderValue(getHeader(req, "call-id"));
        std::string cseq = getHeader(req, "cseq");

        int cseqNum = 0;
        size_t i = 0;
        while (i < cseq.size() && std::isspace((unsigned char)cseq[i])) ++i;
        while (i < cseq.size() && std::isdigit((unsigned char)cseq[i]))
        {
            cseqNum = cseqNum*10 + (cseq[i]-'0');
            ++i;
        }

        std::ostringstream oss;
        oss << "CANCEL " << requestUri << " SIP/2.0\r\n";
        if (!via.empty())  oss << "Via: " << via << "\r\n";
        if (!from.empty()) oss << "From: " << from << "\r\n";
        if (!to.empty())   oss << "To: " << to << "\r\n";
        if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
        oss << "CSeq: " << cseqNum << " CANCEL\r\n";
        oss << "Content-Length: 0\r\n\r\n";
        return oss.str();
    }

    std::string buildSimpleResponse(const SipMessage& req,
                                    int code,
                                    const std::string& reason)
    {
        std::ostringstream oss;
        oss << "SIP/2.0 " << code << " " << reason << "\r\n";

        // 헤더 값 정화 (CRLF 인젝션 방지)
        std::string via     = sanitizeHeaderValue(getHeader(req, "via"));
        std::string from    = sanitizeHeaderValue(getHeader(req, "from"));
        std::string to      = sanitizeHeaderValue(getHeader(req, "to"));
        std::string callId  = sanitizeHeaderValue(getHeader(req, "call-id"));
        std::string cseq    = sanitizeHeaderValue(getHeader(req, "cseq"));

        if (!via.empty())    oss << "Via: "     << via    << "\r\n";
        if (!from.empty())   oss << "From: "    << from   << "\r\n";
        if (!to.empty())     oss << "To: "      << ensureToTag(to) << "\r\n";
        if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
        if (!cseq.empty())   oss << "CSeq: "    << cseq   << "\r\n";

        oss << "Server: SimpleSipServer/0.1\r\n";
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";
        return oss.str();
    }

    std::string buildRegisterOk(const SipMessage& req) 
    {
        std::ostringstream oss;
        oss << "SIP/2.0 200 OK\r\n";

        // 헤더 값 정화 (CRLF 인젝션 방지)
        std::string via     = sanitizeHeaderValue(getHeader(req, "via"));
        std::string from    = sanitizeHeaderValue(getHeader(req, "from"));
        std::string to      = sanitizeHeaderValue(getHeader(req, "to"));
        std::string callId  = sanitizeHeaderValue(getHeader(req, "call-id"));
        std::string cseq    = sanitizeHeaderValue(getHeader(req, "cseq"));
        std::string contact = sanitizeHeaderValue(getHeader(req, "contact"));

        if (!via.empty())     oss << "Via: "     << via                 << "\r\n";
        if (!from.empty())    oss << "From: "    << from                << "\r\n";
        if (!to.empty())      oss << "To: "      << ensureToTag(to)     << "\r\n";
        if (!callId.empty())  oss << "Call-ID: " << callId              << "\r\n";
        if (!cseq.empty())    oss << "CSeq: "    << cseq                << "\r\n";
        if (!contact.empty()) oss << "Contact: " << contact             << "\r\n";

        oss << "Server: SIPLite/0.1\r\n";
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";
        return oss.str();
    }

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
