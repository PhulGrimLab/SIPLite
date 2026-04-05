#include "SipCore.h"
#include "SipParser.h"
#include "Logger.h"

#include <sstream>
#include <algorithm>
#include <charconv>
#include <map>

namespace
{
    constexpr char kRegisterAuthRealm[] = "SIPLite";
    constexpr auto kRegisterNonceTtl = std::chrono::minutes(5);

    const char* transportToken(TransportType transport)
    {
        switch (transport)
        {
        case TransportType::TCP:
            return "TCP";
        case TransportType::TLS:
            return "TLS";
        case TransportType::UDP:
        default:
            return "UDP";
        }
    }

    std::string generateRegisterNonce()
    {
        static constexpr char hex[] = "0123456789abcdef";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 15);

        std::string nonce;
        nonce.reserve(32);
        for (int i = 0; i < 32; ++i)
        {
            nonce.push_back(hex[dist(gen)]);
        }
        return nonce;
    }

    std::map<std::string, std::string> parseDigestParameters(const std::string& header)
    {
        std::map<std::string, std::string> params;
        std::string value = trim(header);
        if (value.size() < 6 || toLower(value.substr(0, 6)) != "digest")
        {
            return params;
        }

        std::size_t pos = 6;
        while (pos < value.size())
        {
            while (pos < value.size() &&
                   (std::isspace(static_cast<unsigned char>(value[pos])) || value[pos] == ','))
            {
                ++pos;
            }
            if (pos >= value.size())
            {
                break;
            }

            std::size_t eq = value.find('=', pos);
            if (eq == std::string::npos)
            {
                break;
            }

            std::string key = toLower(trim(value.substr(pos, eq - pos)));
            pos = eq + 1;

            std::string val;
            if (pos < value.size() && value[pos] == '"')
            {
                ++pos;
                while (pos < value.size())
                {
                    char ch = value[pos];
                    if (ch == '\\' && pos + 1 < value.size())
                    {
                        val.push_back(value[pos + 1]);
                        pos += 2;
                        continue;
                    }
                    if (ch == '"')
                    {
                        ++pos;
                        break;
                    }
                    val.push_back(ch);
                    ++pos;
                }
            }
            else
            {
                std::size_t comma = value.find(',', pos);
                if (comma == std::string::npos)
                {
                    val = trim(value.substr(pos));
                    pos = value.size();
                }
                else
                {
                    val = trim(value.substr(pos, comma - pos));
                    pos = comma + 1;
                }
            }

            if (!key.empty())
            {
                params[key] = val;
            }
        }

        return params;
    }

    bool parseNonceCount(const std::string& nc, std::uint32_t& outNc)
    {
        if (nc.empty() || nc.size() > 8)
        {
            return false;
        }

        outNc = 0;
        for (char ch : nc)
        {
            outNc <<= 4U;
            if (ch >= '0' && ch <= '9')
            {
                outNc |= static_cast<std::uint32_t>(ch - '0');
            }
            else if (ch >= 'a' && ch <= 'f')
            {
                outNc |= static_cast<std::uint32_t>(ch - 'a' + 10);
            }
            else if (ch >= 'A' && ch <= 'F')
            {
                outNc |= static_cast<std::uint32_t>(ch - 'A' + 10);
            }
            else
            {
                return false;
            }
        }

        return true;
    }

    std::string makeDigestResponse(const std::string& username,
                                   const std::string& realm,
                                   const std::string& password,
                                   const std::string& method,
                                   const std::string& uri,
                                   const std::string& nonce,
                                   const std::string& nc,
                                   const std::string& cnonce,
                                   const std::string& qop)
    {
        const std::string ha1 = md5Hex(username + ":" + realm + ":" + password);
        const std::string ha2 = md5Hex(method + ":" + uri);
        if (!qop.empty())
        {
            return md5Hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
        }
        return md5Hex(ha1 + ":" + nonce + ":" + ha2);
    }
}

bool SipCore::handlePacket(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    outResponse.clear();

    if (msg.type != SipType::Request)
    {
        return false;
    }

    // ================================
    // RFC 3261 §8.1.1 필수 헤더 검증
    // Via, From, To, Call-ID, CSeq은 모든 SIP 요청에 필수
    // ================================
    {
        std::string via    = getHeader(msg, "via");
        std::string from   = getHeader(msg, "from");
        std::string to     = getHeader(msg, "to");
        std::string callId = getHeader(msg, "call-id");
        std::string cseq   = getHeader(msg, "cseq");

        if (via.empty() || from.empty() || to.empty() || callId.empty() || cseq.empty())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request - Missing Mandatory Header");
            return true;
        }
    }

    // ================================
    // RFC 3261 §16.3 Max-Forwards 검증
    // 루프 방지를 위해 Max-Forwards를 확인하고 감소시킴
    // ================================
    {
        std::string maxFwdStr = sanitizeHeaderValue(getHeader(msg, "max-forwards"));
        if (!maxFwdStr.empty())
        {
            std::string trimmed = trim(maxFwdStr);
            int maxFwd = -1;
            auto [ptr, ec] = std::from_chars(
                trimmed.data(), trimmed.data() + trimmed.size(), maxFwd);
            if (ec != std::errc{} || ptr != trimmed.data() + trimmed.size() || maxFwd < 0)
            {
                outResponse = buildSimpleResponse(msg, 400, "Bad Request - Invalid Max-Forwards");
                return true;
            }
            if (maxFwd == 0)
            {
                outResponse = buildSimpleResponse(msg, 483, "Too Many Hops");
                return true;
            }
        }
        // Max-Forwards 헤더 미포함 시에는 RFC 3261 §16.6 step 3에 따라
        // 프록시가 기본값(70)을 삽입하여 전달하므로 여기서는 차단하지 않음
    }

    // ================================
    // Content-Length 검증 (RFC 3261 §18.3)
    // Content-Length 헤더 값과 실제 body 크기가 불일치하면 400 반환
    // ================================
    {
        std::string clStr = sanitizeHeaderValue(getHeader(msg, "content-length"));
        if (!clStr.empty())
        {
            std::string trimmed = trim(clStr);
            int contentLen = -1;
            auto [ptr, ec] = std::from_chars(
                trimmed.data(), trimmed.data() + trimmed.size(), contentLen);
            if (ec != std::errc{} || ptr != trimmed.data() + trimmed.size() || contentLen < 0)
            {
                outResponse = buildSimpleResponse(msg, 400, "Bad Request - Invalid Content-Length");
                return true;
            }
            if (static_cast<std::size_t>(contentLen) != msg.body.size())
            {
                outResponse = buildSimpleResponse(msg, 400, "Bad Request - Content-Length Mismatch");
                return true;
            }
        }
    }

    // ================================
    // RFC 3261 §8.2.2.3 Require 헤더 검증
    // 지원하지 않는 옵션 태그가 포함된 경우 420 Bad Extension 반환
    // ================================
    {
        std::string requireHdr = sanitizeHeaderValue(getHeader(msg, "require"));
        if (!requireHdr.empty())
        {
            // 현재 SIPLite는 어떤 SIP 확장도 지원하지 않으므로
            // Require 헤더에 포함된 모든 옵션 태그를 Unsupported로 반환
            std::ostringstream oss;
            oss << "SIP/2.0 420 Bad Extension\r\n";

            std::string via    = sanitizeHeaderValue(getHeader(msg, "via"));
            std::string from   = sanitizeHeaderValue(getHeader(msg, "from"));
            std::string to     = sanitizeHeaderValue(getHeader(msg, "to"));
            std::string callId = sanitizeHeaderValue(getHeader(msg, "call-id"));
            std::string cseq   = sanitizeHeaderValue(getHeader(msg, "cseq"));

            if (!via.empty())    oss << "Via: "     << via    << "\r\n";
            if (!from.empty())   oss << "From: "    << from   << "\r\n";
            if (!to.empty())     oss << "To: "      << ensureToTag(to) << "\r\n";
            if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
            if (!cseq.empty())   oss << "CSeq: "    << cseq   << "\r\n";

            oss << "Unsupported: " << requireHdr << "\r\n";
            oss << "Server: SIPLite/0.1\r\n";
            oss << "Content-Length: 0\r\n";
            oss << "\r\n";

            outResponse = oss.str();
            return true;
        }
    }

    // SIP 메서드 대소문자 구분 없이 처리 - SIP 표준에서는 메서드 이름이 대소문자 구분 없이 처리되어야 한다.
    // 예: "invite", "INVITE", "InViTe" 모두 같은 메서드로 처리되어야 한다.
    // 따라서 메서드 이름을 대문자로 변환하여 비교한다.
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
    else if (methodUpper == "MESSAGE")
    {
        return handleMessage(pkt, msg, outResponse);
    }
    else if (methodUpper == "SUBSCRIBE")
    {
        return handleSubscribe(pkt, msg, outResponse);
    }
    else if (methodUpper == "NOTIFY")
    {
        return handleNotify(pkt, msg, outResponse);
    }

    // Unsupported method
    outResponse = buildSimpleResponse(msg, 501, "Not Implemented");
    return true;
}

// SIP 응답 처리 함수인 handleResponse는 SIP 흐름 관리에 중요한 역할을 한다.
// SIP 응답 메시지의 상태 코드와 CSeq 헤더를 기반으로 적절한 처리를 수행하며, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송한다.
// SIP 응답 처리 중에는 트랜잭션 상태 업데이트, Dialog 생성, ACK 전송 여부 결정 등의 처리가 수행된다.
// SIP 응답 처리 후, 필요한 경우 sender_ 콜백을 통해 원본 응답 메시지와 ACK 메시지를 전송할 수 있도록 구현되어 있다.
bool SipCore::handleResponse(const UdpPacket& pkt, const SipMessage& msg)
{
    // SIP 응답은 SIP 흐름(예: INVITE → 100 Trying → 180 Ringing → 200 OK 등)의 일부로 처리된다.
    // 따라서 응답 메시지의 상태 코드와 CSeq 헤더를 기반으로 적절한 처리를 수행해야 한다.
    // 예: INVITE에 대한 100 Trying/180 Ringing/200 OK 응답 처리, CANCEL에 대한 200 OK 응답 처리 등.

    // SIP 응답은 SIP 흐름의 일부로 처리되므로, 일반적으로 외부에서 직접 응답을 생성하여 반환하는 경우는 드물다.
    // 대신, SIP 흐름 처리 중에 필요한 경우 sender_ 콜백을 통해 네트워크로 응답을 전송하는 방식으로 구현된다.

    std::string callId = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string cseq  = sanitizeHeaderValue(getHeader(msg, "cseq"));

    if (callId.empty() || cseq.empty())
    {
        return false;
    }

    // CSeq 헤더에서 숫자 부분만 추출하여 정수로 변환
    // CSeq 헤더는 일반적으로 "CSeq: 123 INVITE"와 같은 형식으로 되어 있다.
    // 따라서 숫자 부분만 추출하여 정수로 변환해야 한다.
    int cseqNum = parseCSeqNum(cseq);
    if (cseqNum < 0)
    {
        return false;
    }

    // CSeq 메서드 확인: pendingInvites_는 INVITE 트랜잭션만 관리
    // INVITE 이외의 응답(CANCEL 200 OK, CANCEL 400 등)은 프록시에서 소비
    // 일부 SIP 구현체는 CANCEL 거부 시 CSeq 메서드를 다르게 보낼 수 있으므로
    // INVITE만 통과시키는 화이트리스트 방식이 안전함
    {
        std::string cseqMethod = parseCSeqMethod(cseq);
        std::string cseqMethodUpper = cseqMethod;
        std::transform(cseqMethodUpper.begin(), cseqMethodUpper.end(),
                       cseqMethodUpper.begin(), ::toupper);
        // CSeq 메서드가 존재하고 INVITE가 아닌 경우 → 소비 (CANCEL, BYE 등의 응답)
        // CSeq 메서드가 비어있는 경우(파싱 실패) → 안전하게 INVITE로 간주하여 통과
        if (!cseqMethodUpper.empty() && cseqMethodUpper != "INVITE")
        {
            // Non-2xx 응답 (CANCEL 거부 등)은 경고 로그 출력
            if (msg.statusCode >= 400)
            {
                Logger::instance().info("[handleResponse] Non-INVITE error consumed:"
                    " method=" + cseqMethodUpper
                    + " status=" + std::to_string(msg.statusCode)
                    + " callId=" + callId
                    + " from=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
            }
            return true;  // Non-INVITE 응답 소비 — 추가 처리 불필요
        }
    }

    // callId + cseqNum을 키로 하여 pendingInvites_에서 해당 INVITE 트랜잭션이 존재하는지 확인
    // SIP 응답은 일반적으로 INVITE 트랜잭션과 연관되어 처리된다.
    // 따라서 응답 메시지의 call-id와 cseq 헤더를 기반으로 해당 트랜잭션이 pendingInvites_에 존재하는지 확인해야 한다.
    // 예: INVITE 트랜잭션이 존재하는 경우, 100 Trying/180 Ringing/200 OK 응답에 따라 트랜잭션 상태를 업데이트하거나, 
    // CANCEL 트랜잭션이 존재하는 경우 200 OK 응답에 따라 트랜잭션을 종료하는 등의 처리가 필요할 수 있다.
    std::string key = callId + ":" + std::to_string(cseqNum);

    // Collect info to send outside locks
    std::string fwdIp;
    uint16_t fwdPort = 0;
    TransportType fwdTransport = TransportType::UDP;
    std::string fwdData;
    std::string ackData;
    std::string ackIp;
    uint16_t ackPort = 0;
    TransportType ackTransport = TransportType::UDP;

    {
        // 올바른 뮤텍스 순서: callMutex_ → pendingInvMutex_ → dlgMutex_
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        // callId + cseqNum을 키로 하여 pendingInvites_에서 해당 INVITE 트랜잭션이 존재하는지 확인
        // SIP 응답은 일반적으로 INVITE 트랜잭션과 연관되어 처리된다.
        // 따라서 응답 메시지의 call-id와 cseq 헤더를 기반으로 해당 트랜잭션이 pendingInvites_에 존재하는지 확인해야 한다.
        auto it = pendingInvites_.find(key);
        if (it == pendingInvites_.end())
        {
            Logger::instance().info("[handleResponse] pendingInvite not found: key=" + key
                + " status=" + std::to_string(msg.statusCode)
                + " from=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort)
                + " pendingCount=" + std::to_string(pendingInvites_.size()));
            return false;
        }

        // === COMPLETED 상태에서 3xx-6xx 재전송 흡수 (RFC 3261 §17.1.1.2 Timer D) ===
        // 이미 처리된 에러 응답의 재전송인 경우, ACK만 다시 보내고 caller에게는 재전달하지 않음
        // callee가 ACK를 못 받으면(UDP 손실 등) 동일한 에러 응답을 재전송하는데,
        // pendingInvite가 COMPLETED 상태로 남아있어야 ACK를 재전송할 수 있음
        if (it->second.state == TxState::COMPLETED && msg.statusCode >= 300)
        {
            std::string ack = buildAckForPending(it->second, pkt.data);
            if (!ack.empty())
            {
                ackIp = pkt.remoteIp;
                ackPort = pkt.remotePort;
                ackTransport = pkt.transport;
                ackData = std::move(ack);
            }
            // fwdData는 비워둠 — caller에게 재전달하지 않음 (이미 첫 응답에서 전달 완료)
        }
        else
        {

        // Collect forwarding info (send outside lock)
        // 프록시가 추가한 Via를 제거하여 caller에게 전달 (RFC 3261 §16.7)
        fwdIp = it->second.callerIp;
        fwdPort = it->second.callerPort;
        fwdTransport = it->second.callerTransport;
        fwdData = removeTopVia(pkt.data);

        // 상태 코드에 따라 트랜잭션 상태 업데이트
        // 1xx: provisional 응답 → 상태를 PROCEEDING으로 업데이트
        // 2xx: 성공 응답 → 상태를 COMPLETED로 업데이트, Dialog 생성 필요 여부 확인
        // 3xx-6xx: 에러 응답 → 상태를 COMPLETED로 업데이트, 프록시가 ACK 생성 필요 여부 확인 (RFC 3261 §16.7)
        if (msg.statusCode < 200)
        {
            it->second.state = TxState::PROCEEDING;
            it->second.lastResponse = pkt.data;
            it->second.attempts = 0;
            // RFC 3261 §16.7: provisional 응답 수신 시 Timer C 리셋
            it->second.timerCExpiry = std::chrono::steady_clock::now()
                + std::chrono::seconds(SipConstants::TIMER_C_SEC);
        }
        else
        {
            it->second.state = TxState::COMPLETED;
            it->second.lastResponse = pkt.data;
            it->second.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(32);

            if (msg.statusCode >= 200 && msg.statusCode < 300)
            {
                // 2xx 성공 응답: Dialog 생성
                // 2xx 응답에 대한 Dialog 생성은 ACK 전송 필요 여부와 별개로 처리됩니다.
                // 2xx 응답이 수신되면 Dialog를 생성하여 SIP 흐름을 관리할 수 있도록 합니다.
                // CSeq 헤더에서 메서드 이름을 추출하여 대문자로 변환한 후, INVITE인 경우에만 Dialog를 생성하도록 합니다.
                // CSeq 헤더에서 메서드 이름 추출은 parseCSeqMethod 함수를 사용하여 수행할 수 있습니다.
                std::string method = parseCSeqMethod(cseq);
                std::string methodUpper = method;
                std::transform(methodUpper.begin(), methodUpper.end(), methodUpper.begin(), ::toupper);

                if (methodUpper.rfind("INVITE",0) == 0)
                {
                    // 2xx 응답이 INVITE에 대한 것인 경우에만 Dialog를 생성한다.
                    // Dialog 생성 시, callId, callerTag(From 헤더의 tag), 
                    // calleeTag(To 헤더의 tag), callerIp/Port, calleeIp/Port, cseqNum, 생성 시간 등을 설정한다.  
                    // 또한, 2xx 응답에 SDP 바디가 포함된 경우, 
                    // ActiveCall의 lastSdp 및 lastSdpContentType 필드에 해당 정보를 저장하여 SIP 흐름 관리에 활용할 수 있도록 한다.
                    // Dialog 생성은 SIP 흐름 관리에 중요한 역할을 한다. 
                    // Dialog를 통해 SIP 메시지의 흐름을 추적하고, ACK 전송 여부를 결정하는 등의 처리를 수행할 수 있다.
                    auto acIt = activeCalls_.find(callId);
                    if (acIt != activeCalls_.end())
                    {
                        Dialog dlg;
                        dlg.callId = callId;
                        dlg.callerTag = acIt->second.fromTag;
                        std::string toHdr = sanitizeHeaderValue(getHeader(msg, "to"));
                        dlg.calleeTag = extractTagFromHeader(toHdr);
                        dlg.callerIp = it->second.callerIp;
                        dlg.callerPort = it->second.callerPort;
                        dlg.callerTransport = it->second.callerTransport;
                        dlg.calleeIp = pkt.remoteIp;
                        dlg.calleePort = pkt.remotePort;
                        dlg.calleeTransport = pkt.transport;
                        dlg.cseq = cseqNum;
                        dlg.created = std::chrono::steady_clock::now();
                        dlg.confirmed = false;

                        // callee의 Contact 헤더에서 remote target 추출 (in-dialog 라우팅용)
                        std::string contactHdr200 = sanitizeHeaderValue(getHeader(msg, "contact"));
                        dlg.remoteTarget = extractUriFromHeader(contactHdr200);

                        // caller의 Contact URI를 PendingInvite에서 복사 (BYE 전달 시 사용)
                        dlg.callerContact = it->second.callerContact;

                        // ActiveCall의 toTag를 callee의 실제 태그로 갱신
                        // (handleInvite에서 생성한 프록시 태그를 callee의 태그로 교체)
                        if (!dlg.calleeTag.empty())
                        {
                            acIt->second.toTag = dlg.calleeTag;
                        }

                        std::string body = msg.body;
                        std::string ctype = sanitizeHeaderValue(getHeader(msg, "content-type"));
                        if (!body.empty())
                        {
                            acIt->second.lastSdp = body;
                            acIt->second.lastSdpContentType = ctype.empty() ? "application/sdp" : ctype;
                        }
                        
                        // Dialog를 생성하여 dialogs_ 맵에 저장한다.
                        dialogs_[callId] = std::move(dlg);
                    }
                }

                // ACK 전송 필요 여부 확인
                // 2xx 응답에 대한 ACK는 SIP 흐름 관리에 중요한 역할을 한다.
                // ACK 전송 여부는 Dialog의 confirmed 필드로 관리할 수 있다.
                // ACK 전송이 필요한 경우, buildAckForPending 함수를 사용하여 ACK 메시지를 생성하고,
                // sender_ 콜백을 통해 네트워크로 전송할 수 있도록 한다.
                auto dit = dialogs_.find(callId);
                if (dit != dialogs_.end() && dit->second.confirmed)
                {
                    auto pit = pendingInvites_.find(key);
                    if (pit != pendingInvites_.end())
                    {
                        std::string ack = buildAckForPending(pit->second, pkt.data);
                        if (!ack.empty())
                        {
                            ackIp = pkt.remoteIp;
                            ackPort = pkt.remotePort;
                            ackTransport = pkt.transport;
                            // ACK 메시지를 생성하여 ackData에 저장한다.
                            ackData = std::move(ack);
                        }
                    }
                }
            }
            else
            {
                // 3xx-6xx 에러 응답: 프록시가 ACK 생성 필요 (RFC 3261 §16.7)
                // 3xx-6xx 응답에 대한 ACK 생성 여부는 SIP 흐름 관리에 중요한 역할을 한다.
                // 프록시가 ACK를 생성해야 하는 경우, buildAckForPending 함수를 사용하여 ACK 메시지를 생성하고, 
                // sender_ 콜백을 통해 네트워크로 전송할 수 있도록 한다.
                std::string ack = buildAckForPending(it->second, pkt.data);
                if (!ack.empty())
                {
                    ackIp = pkt.remoteIp;
                    ackPort = pkt.remotePort;
                    ackTransport = pkt.transport;
                    // ACK 메시지를 생성하여 ackData에 저장한다.
                    ackData = std::move(ack);
                }

                // 에러 응답 시 ActiveCall, Dialog 정리
                // PendingInvite는 COMPLETED 상태로 유지 — Timer D(32초) 동안
                // callee의 에러 응답 재전송을 흡수하기 위함 (RFC 3261 §17.1.1.2)
                // cleanupStaleTransactions()가 expiry 이후 자동 정리함
                activeCalls_.erase(callId);
                dialogs_.erase(callId);
            }
        }

        } // else (non-COMPLETED 처리 끝)
    } // all locks released

    // Send outside locks (#3 fix)
    // SIP 응답 처리 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송합니다.
    // SIP 응답 처리 중에 수집된 정보를 기반으로, 
    // fwdData(원본 응답 메시지)와 ackData(생성된 ACK 메시지)를 sender_ 콜백을 통해 전송합니다.
    if (sender_)
    {
        // fwdData는 원본 응답 메시지로, ACK는 SIP 흐름 관리에 필요한 경우에만 생성된다.
        // 따라서, fwdData와 ackData가 모두 존재하는 경우에는 원본 응답 메시지와 ACK 메시지를 모두 전송할 수 있도록 한다.
        if (!fwdData.empty())
        {
            sender_(fwdIp, fwdPort, fwdData, fwdTransport);
        }

        // ACK는 SIP 흐름 관리에 필요한 경우에만 생성되므로, ackData가 존재하는 경우에만 전송한다.
        if (!ackData.empty())
        {
            sender_(ackIp, ackPort, ackData, ackTransport);
        }
    }

    return true;
}

// SIP REGISTER 요청 처리 함수인 handleRegister는 SIP 등록 관리에 중요한 역할을 한다.
// SIP REGISTER 요청 메시지에서 To 헤더와 Contact 헤더를 추출하여 등록 정보를 관리하며, 
// Expires 헤더를 기반으로 등록의 유효 기간을 설정한다.
// SIP REGISTER 요청 처리 중에는 등록 정보의 추가, 갱신, 삭제 등의 처리가 수행되며, 
// 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있다.
// SIP REGISTER 요청 처리 후, 등록 정보가 성공적으로 추가,갱신, 삭제된 경우에는 true를 반환하고, 
// 요청 메시지에 필요한 헤더가 누락된 경우에는 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤 true를 반환하도록 한다.
// REGISTER는 어떤 경우든 SIP 응답을 생성할 수 있으므로 항상 true를 반환하도록 한다.
bool SipCore::handleRegister(const UdpPacket& pkt,
                             const SipMessage& msg,
                             std::string& outResponse)
{
    std::string toHdr      = sanitizeHeaderValue(getHeader(msg, "to"));
    std::string contactHdr = sanitizeHeaderValue(getHeader(msg, "contact"));

    if (toHdr.empty() || contactHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    std::string aor = extractUriFromHeader(toHdr);
    if (aor.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // XML에 등록된 단말만 REGISTER 허용 (사용자 ID로 매칭)
    std::string matchedAor;
    Registration staticReg;
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = findByUser_(aor);
        if (it == regs_.end())
        {
            outResponse = buildSimpleResponse(msg, 404, "Not Found");
            return true;
        }
        if (!it->second.isStatic)
        {
            outResponse = buildSimpleResponse(msg, 403, "Forbidden");
            return true;
        }
        matchedAor = it->first;
        staticReg = it->second;
    }

    if (!staticReg.authPassword.empty())
    {
        const std::string authHdr = sanitizeHeaderValue(getHeader(msg, "authorization"));
        const auto authParams = parseDigestParameters(authHdr);
        bool staleNonce = false;
        bool authorized = false;

        if (!authParams.empty())
        {
            const auto usernameIt = authParams.find("username");
            const auto realmIt = authParams.find("realm");
            const auto nonceIt = authParams.find("nonce");
            const auto uriIt = authParams.find("uri");
            const auto responseIt = authParams.find("response");
            const auto qopIt = authParams.find("qop");
            const auto ncIt = authParams.find("nc");
            const auto cnonceIt = authParams.find("cnonce");
            const auto algorithmIt = authParams.find("algorithm");

            if (usernameIt != authParams.end() &&
                realmIt != authParams.end() &&
                nonceIt != authParams.end() &&
                uriIt != authParams.end() &&
                responseIt != authParams.end())
            {
                const std::string expectedUser = extractUserFromUri(matchedAor);
                const std::string realm = realmIt->second;
                const std::string qop = (qopIt != authParams.end()) ? toLower(qopIt->second) : "";
                const std::string nc = (ncIt != authParams.end()) ? ncIt->second : "";
                const std::string cnonce = (cnonceIt != authParams.end()) ? cnonceIt->second : "";
                const bool algorithmOk = (algorithmIt == authParams.end()) ||
                                         toLower(algorithmIt->second) == "md5";

                if (usernameIt->second == expectedUser &&
                    realm == kRegisterAuthRealm &&
                    algorithmOk &&
                    (qop.empty() || qop == "auth") &&
                    uriIt->second == msg.requestUri)
                {
                    bool nonceOk = false;
                    std::uint32_t parsedNc = 0;
                    bool hasParsedNc = false;
                    if (qop.empty())
                    {
                        std::lock_guard<std::mutex> authLock(authMutex_);
                        auto nonceState = registerNonces_.find(nonceIt->second);
                        if (nonceState != registerNonces_.end() &&
                            nonceState->second.expiresAt > std::chrono::steady_clock::now())
                        {
                            nonceOk = true;
                        }
                        else if (nonceState != registerNonces_.end())
                        {
                            registerNonces_.erase(nonceState);
                            staleNonce = true;
                        }
                    }
                    else if (!nc.empty() && !cnonce.empty())
                    {
                        if (parseNonceCount(nc, parsedNc))
                        {
                            hasParsedNc = true;
                            std::lock_guard<std::mutex> authLock(authMutex_);
                            auto nonceState = registerNonces_.find(nonceIt->second);
                            if (nonceState != registerNonces_.end() &&
                                nonceState->second.expiresAt > std::chrono::steady_clock::now())
                            {
                                nonceOk = parsedNc > nonceState->second.lastNonceCount;
                            }
                            else if (nonceState != registerNonces_.end())
                            {
                                registerNonces_.erase(nonceState);
                                staleNonce = true;
                            }
                        }
                    }

                    if (nonceOk)
                    {
                        const std::string expectedResponse = makeDigestResponse(
                            expectedUser,
                            kRegisterAuthRealm,
                            staticReg.authPassword,
                            "REGISTER",
                            uriIt->second,
                            nonceIt->second,
                            nc,
                            cnonce,
                            qop);
                        authorized = toLower(responseIt->second) == expectedResponse;
                        if (authorized && hasParsedNc)
                        {
                            std::lock_guard<std::mutex> authLock(authMutex_);
                            auto nonceState = registerNonces_.find(nonceIt->second);
                            if (nonceState != registerNonces_.end() &&
                                parsedNc > nonceState->second.lastNonceCount)
                            {
                                nonceState->second.lastNonceCount = parsedNc;
                            }
                        }
                    }
                }
            }
        }

        if (!authorized)
        {
            std::string nonce = generateRegisterNonce();
            {
                std::lock_guard<std::mutex> authLock(authMutex_);
                const auto now = std::chrono::steady_clock::now();
                for (auto it = registerNonces_.begin(); it != registerNonces_.end();)
                {
                    if (it->second.expiresAt <= now)
                    {
                        it = registerNonces_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
                registerNonces_[nonce] = {
                    std::chrono::steady_clock::now() + kRegisterNonceTtl,
                    0
                };
            }
            outResponse = buildRegisterAuthChallenge(msg, nonce, staleNonce);
            return true;
        }
    }

    // Expires 헤더 또는 Contact 헤더의 expires 파라미터에서 유효 시간(TTL)을 추출하여 등록의 만료 시점을 계산한다.
    // SIP REGISTER 요청 처리 중에는 등록 정보의 추가, 갱신, 삭제 등의 처리가 수행되며, 
    // 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있다.
    // SIP REGISTER 요청 처리 후, 등록 정보가 성공적으로 추가, 갱신, 삭제된 경우에는 true를 반환하고, 
    // 요청 메시지에 필요한 헤더가 누락된 경우에는 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤 true를 반환하도록 한다.
    int expiresSec = SipConstants::DEFAULT_EXPIRES_SEC;
    std::string expHdr = sanitizeHeaderValue(getHeader(msg, "expires"));
    if (!expHdr.empty())
    {
        std::string trimmed = trim(expHdr);
        bool validNumber = !trimmed.empty() && trimmed.size() <= 10;
        for (char c : trimmed)
        {
            if (c < '0' || c > '9')
            {
                validNumber = false;
                break;
            }
        }

        if (!validNumber)
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request - Invalid Expires");
            return true;
        }

        int value = 0;
        auto [ptr, ec] = std::from_chars(
            trimmed.data(), trimmed.data() + trimmed.size(), value);

        if (ec != std::errc{} || ptr != trimmed.data() + trimmed.size())
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request - Invalid Expires");
            return true;
        }

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

    // Expires: 0은 등록 해제 (RFC 3261 Section 10.2.2) (#11 fix)
    // Expires 헤더 또는 Contact 헤더의 expires 파라미터에서 유효 시간(TTL)을 추출하여 등록의 만료 시점을 계산한다.
    // SIP REGISTER 요청 처리 중에는 등록 정보의 추가, 갱신, 삭제 등의 처리가 수행되며, 
    // 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있다.
    // SIP REGISTER 요청 처리 후, 등록 정보가 성공적으로 추가, 갱신, 삭제된 경우에는 true를 반환하고, 
    // 요청 메시지에 필요한 헤더가 누락된 경우에는 
    // 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤 true를 반환하도록 한다.
    if (expiresSec == 0)
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = regs_.find(matchedAor);
        if (it != regs_.end())
        {
            if (it->second.isStatic)
            {
                // 정적 등록 단말은 삭제하지 않고 로그인 상태만 해제
                it->second.loggedIn = false;
            }
            else
            {
                regs_.erase(it);
            }
        }
        outResponse = buildRegisterOk(msg);
        return true;
    }

    Registration reg;
    reg.aor      = matchedAor;  // XML에 등록된 원래 AOR 유지
    reg.contact  = contactHdr;
    reg.ip       = pkt.remoteIp;
    reg.port     = pkt.remotePort;
    reg.transport = pkt.transport;
    reg.authPassword = staticReg.authPassword;
    reg.expiresAt = std::chrono::steady_clock::now() +
                    std::chrono::seconds(expiresSec);
    reg.loggedIn = true;
    reg.isStatic = staticReg.isStatic;

    {
        std::lock_guard<std::mutex> lock(regMutex_);
        regs_[matchedAor] = reg;
    }

    outResponse = buildRegisterOk(msg);
    return true;
}

// SIP INVITE 요청 처리 함수인 handleInvite는 SIP 통화 관리에 중요한 역할을 한다.
// SIP INVITE 요청 메시지에서 To 헤더, From 헤더, Call-ID 헤더, CSeq 헤더를 추출하여 SIP 통화 흐름을 관리하며,
// SIP INVITE 요청 처리 중에는 트랜잭션 상태 업데이트, Dialog 생성, ACK 전송 여부 결정 등의 처리가 수행된다.
// SIP INVITE 요청 처리 후, 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있다.
// SIP INVITE 요청 처리 후, SIP 흐름 관리에 필요한 경우에는 sender_ 콜백을 통해 네트워크로 메시지를 전송할 수 있도록 구현되어 있다.
// SIP INVITE 요청 처리 중에 필요한 헤더가 누락된 경우에는 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤 true를 반환하도록 한다. 
// SIP INVITE 요청은 SIP 흐름 관리에 중요한 역할을 하므로, SIP 흐름 관리에 필요한 처리를 수행한 후에는 true를 반환하도록 한다.
bool SipCore::handleInvite(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    std::string toHdr     = sanitizeHeaderValue(getHeader(msg, "to"));
    std::string fromHdr   = sanitizeHeaderValue(getHeader(msg, "from"));
    std::string callId    = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string cseqHdr   = sanitizeHeaderValue(getHeader(msg, "cseq"));

    if (toHdr.empty() || fromHdr.empty() || callId.empty() || cseqHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // To 헤더에서 URI를 추출하여 등록된 사용자 정보와 매칭한다.
    std::string toUri = extractUriFromHeader(toHdr);

    Registration regCopy;
    bool found = false;
    bool knownButOffline = false;  // isStatic이지만 loggedIn=false 또는 expires 만료

    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = findByUser_(toUri);
        if (it != regs_.end())
        {
            if (it->second.expiresAt > std::chrono::steady_clock::now()
                && it->second.loggedIn)
            {
                regCopy = it->second;
                found = true;
            }
            else if (it->second.isStatic)
            {
                // 사전 등록(XML)된 단말이지만 현재 오프라인
                knownButOffline = true;
            }
        }
    }

    if (!found)
    {
        if (knownButOffline)
        {
            // RFC 3261 §21.4.18: 등록된 사용자이지만 현재 이용 불가
            outResponse = buildSimpleResponse(msg, 480, "Temporarily Unavailable");
        }
        else
        {
            // 완전히 알 수 없는 사용자
            outResponse = buildSimpleResponse(msg, 404, "Not Found");
        }
        return true;
    }

    // CSeq를 가장 먼저 파싱 — 실패 시 100 Trying 전송 전에 반환 (#9 fix)
    // CSeq 헤더에서 숫자 부분만 추출하여 정수로 변환
    // CSeq 헤더는 일반적으로 "CSeq: 123 INVITE"와 같은 형식으로 되어 있다.
    // 따라서 숫자 부분만 추출하여 정수로 변환해야 한다.
    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    std::string key = callId + ":" + std::to_string(cseqNum);

    // ===== 재전송 체크를 ActiveCall 생성보다 먼저 수행 =====
    // 재전송인 경우 ActiveCall을 덮어쓰지 않고 즉시 반환하여,
    // 기존 트랜잭션 상태가 보존되도록 한다.
    std::string retransmitData;
    bool isRetransmit = false;
    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto it = pendingInvites_.find(key);
        if (it != pendingInvites_.end())
        {
            // COMPLETED 상태(이미 거절/종료된 트랜잭션)는 재전송이 아닌 새 요청으로 처리
            // 이전 트랜잭션이 아직 정리되지 않은 경우에도 새로운 통화를 정상 처리할 수 있도록 한다.
            if (it->second.state == TxState::COMPLETED)
            {
                pendingInvites_.erase(it);
                // isRetransmit = false 유지 → 새 INVITE로 진행
            }
            else
            {
                if (!it->second.lastResponse.empty())
                {
                    retransmitData = it->second.lastResponse;
                }
                else
                {
                    retransmitData = buildSimpleResponse(msg, 100, "Trying");
                }
                isRetransmit = true;
            }
        }
    }

    // 재전송인 경우 ActiveCall 생성/덮어쓰기 없이 즉시 반환
    if (isRetransmit)
    {
        if (sender_ && !retransmitData.empty())
        {
            sender_(pkt.remoteIp, pkt.remotePort, retransmitData, pkt.transport);
        }
        return true;
    }

    // ===== 재전송이 아닌 새로운 INVITE만 여기 도달 =====

    // 100 Trying은 새로운 INVITE에 대해서만 전송
    if (sender_)
    {
        sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"), pkt.transport);
    }
    else
    {
        outResponse = buildSimpleResponse(msg, 100, "Trying");
    }

    // toTag는 로컬 변수 사용 — activeCalls_ 접근 시 callMutex_ 필요 (data race 방지)
    std::string fromTag = extractTagFromHeader(fromHdr);
    std::string toTag = generateTag();

    // 프록시 Via가 추가된 INVITE를 먼저 생성 — CANCEL/ACK 생성 시에도 동일한 Via가 필요
    // RFC 3261 §16.6 step 6: Request-URI를 callee의 Contact 주소로 변경
    std::string contactUri = extractUriFromHeader(regCopy.contact);
    std::string fwdInvite = addProxyVia(pkt.data, pkt.transport);
    fwdInvite = addRecordRoute(fwdInvite, pkt.transport);  // Record-Route 추가 — in-dialog 요청이 프록시를 경유하도록 보장
    fwdInvite = decrementMaxForwards(fwdInvite);  // RFC 3261 §16.6 step 3
    if (!contactUri.empty())
    {
        fwdInvite = rewriteRequestUri(fwdInvite, contactUri);
    }

    // 보류 CANCEL 처리용 변수 (락 밖에서 네트워크 전송을 위해)
    bool deferredCancel = false;
    std::string resp487ForCaller;

    // ===== ActiveCall + PendingInvite를 하나의 락 구간에서 원자적으로 생성 =====
    // 이 두 자료구조 생성 사이에 gap이 있으면 CANCEL/거절 응답이 도착했을 때
    // pendingInvites_에 키가 없어서 무시되는 경합 조건이 발생할 수 있다.
    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);

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
        call.callerTransport = pkt.transport;
        call.calleeIp = regCopy.ip;
        call.calleePort = regCopy.port;
        call.calleeTransport = regCopy.transport;
        call.startTime = std::chrono::steady_clock::now();
        call.confirmed = false;
        activeCalls_[callId] = call;

        PendingInvite pi;
        pi.callerIp = pkt.remoteIp;
        pi.callerPort = pkt.remotePort;
        pi.callerTransport = pkt.transport;
        pi.calleeIp = regCopy.ip;
        // caller의 Contact URI 저장 (BYE 전달 시 Request-URI 재작성용)
        {
            std::string callerContactHdr = sanitizeHeaderValue(getHeader(msg, "contact"));
            pi.callerContact = extractUriFromHeader(callerContactHdr);
        }
        pi.calleePort = regCopy.port;
        pi.calleeTransport = regCopy.transport;
        // 프록시 Via가 추가된 버전을 저장하여, CANCEL/ACK 생성 시 callee가 받은 Via와 일치하도록 함
        pi.origRequest = fwdInvite;
        // caller의 원본 INVITE를 저장하여, 487 응답 생성 시 프록시 Via 없는 버전을 사용
        pi.callerRequest = pkt.data;
        pi.ts = std::chrono::steady_clock::now();
        pi.state = TxState::TRYING;
        pi.timerCExpiry = pi.ts + std::chrono::seconds(SipConstants::TIMER_C_SEC);
        pi.lastResponse = buildSimpleResponse(msg, 100, "Trying");

        pendingInvites_[key] = std::move(pi);

        // ===== 보류 CANCEL 확인 =====
        // CANCEL이 이 INVITE보다 먼저 다른 워커 스레드에서 처리되어
        // pendingCancels_에 등록되어 있을 수 있다. 발견되면 즉시 취소 처리.
        auto cancelIt = pendingCancels_.find(key);
        if (cancelIt != pendingCancels_.end())
        {
            pendingCancels_.erase(cancelIt);
            deferredCancel = true;
            Logger::instance().info("[handleInvite] Deferred CANCEL found, cancelling immediately: key=" + key);

            // caller에게 보낼 487 Request Terminated 생성
            // msg는 caller의 원본 INVITE(프록시 Via 없음)이므로 Via branch가 일치
            resp487ForCaller = buildSimpleResponse(msg, 487, "Request Terminated");

            // 자료구조 정리
            pendingInvites_.erase(key);
            activeCalls_.erase(callId);
            dialogs_.erase(callId);
        }
    } // 락 해제

    // 보류 CANCEL이 있었으면 락 밖에서 네트워크 전송
    if (deferredCancel)
    {
        if (sender_)
        {
            // 이미 취소된 통화이므로 callee에게 INVITE 전송 불필요
            // INVITE+CANCEL을 동시에 보내면 UDP 순서 역전으로 CANCEL이 먼저 도달할 수 있음
            // caller에게 487 응답만 전송
            if (!resp487ForCaller.empty())
            {
                sender_(pkt.remoteIp, pkt.remotePort, resp487ForCaller, pkt.transport);
            }
        }

        outResponse.clear();
        return true;
    }

    if (sender_)
    {
        sender_(regCopy.ip, regCopy.port, fwdInvite, regCopy.transport);
    }

    // 프록시는 180 Ringing을 직접 생성하지 않음 — callee의 provisional 응답이
    // handleResponse를 통해 caller에게 전달됨 (To 태그 일관성 보장)
    outResponse.clear();

    return true;
}

// SIP ACK 요청 처리 함수인 handleAck는 SIP 흐름 관리에 중요한 역할을 한다.
// SIP ACK 요청 메시지에서 Call-ID 헤더와 CSeq 헤더를 추출하여 SIP 통화 흐름을 관리하며, 
// SIP ACK 요청 처리 중에는 트랜잭션 상태 업데이트, Dialog 상태 업데이트, pendingInvites_에서 트랜잭션 제거 등의 처리가 수행된다.
// SIP ACK 요청 처리 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 ACK 메시지를 전송할 수 있도록 구현되어 있다.
// SIP ACK 요청 처리 중에 필요한 헤더가 누락된 경우에는 false를 반환하여 SIP ACK 요청이 올바르게 처리되지 않았음을 나타내도록 한다. 
// SIP ACK 요청이 올바르게 처리된 경우에는 true를 반환한다.     
bool SipCore::handleAck(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse)
{
    std::string callId = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string cseqHdr = sanitizeHeaderValue(getHeader(msg, "cseq"));

    if (callId.empty() || cseqHdr.empty())
    {
        return false;
    }

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        return false;
    }

    // Capture callee info under lock, send outside
    std::string ackFwdIp;
    uint16_t ackFwdPort = 0;
    TransportType ackFwdTransport = TransportType::UDP;
    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            DialogPeerSide side = classifyDialogPeerSide(it->second, msg, pkt);
            Logger::instance().info("[handleAck] ActiveCall found: callId=" + callId
                + " callerIp=" + it->second.callerIp + ":" + std::to_string(it->second.callerPort)
                + " calleeIp=" + it->second.calleeIp + ":" + std::to_string(it->second.calleePort)
                + " pktFrom=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));

            if (side == DialogPeerSide::Caller)
            {
                it->second.confirmed = true;
                ackFwdIp = it->second.calleeIp;
                ackFwdPort = it->second.calleePort;
                ackFwdTransport = it->second.calleeTransport;
            }
            else if (side == DialogPeerSide::Callee)
            {
                it->second.confirmed = true;
            }
            else
            {
                Logger::instance().error("[handleAck] ACK source mismatch: callId=" + callId
                    + " pktFrom=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
            }
        }
        else
        {
            Logger::instance().error("[handleAck] ActiveCall NOT found: callId=" + callId
                + " pktFrom=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
        }

        auto dit = dialogs_.find(callId);
        if (dit != dialogs_.end())
        {
            dit->second.confirmed = true;   // Dialog의 confirmed 필드를 true로 설정하여 ACK가 수신되었음을 표시한다.
        }

        std::string key = callId + ":" + std::to_string(cseqNum);
        pendingInvites_.erase(key); // ACK이 수신되면 해당 트랜잭션을 pendingInvites_에서 제거하여 SIP 흐름 관리에 반영한다.
    }

    // Send ACK to callee outside all locks
    if (sender_ && !ackFwdIp.empty())
    {
        // ACK에 프록시 Via 추가, Max-Forwards 감소, Route 제거 후 전달
        std::string fwdAck = addProxyVia(pkt.data, pkt.transport);
        fwdAck = decrementMaxForwards(fwdAck);
        fwdAck = stripOwnRoute(fwdAck, pkt.transport);
        sender_(ackFwdIp, ackFwdPort, fwdAck, ackFwdTransport);
    }

    // SIP ACK 요청은 일반적으로 SIP 흐름 관리에 필요한 처리를 수행한 후, 
    // SIP 응답 메시지를 생성하여 outResponse에 반환하지 않으므로, outResponse를 빈 문자열로 설정하여 반환한다.
    outResponse.clear();

    return true;
}

// SIP BYE 요청 처리 함수인 handleBye는 SIP 통화 종료 관리를 수행한다.
// SIP BYE 요청 메시지에서 Call-ID 헤더를 추출하여 SIP 통화 흐름을 관리하며, 
// SIP BYE 요청 처리 중에는 Dialog에서 상대방 정보 조회, ActiveCall에서 상대방 정보 조회, pendingInvites_ 정리 등의 처리가 수행된다.
// SIP BYE 요청 처리 후, 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있으며,
// SIP BYE 요청이 올바르게 처리된 경우에는 true를 반환한다. 
// SIP BYE 요청 처리 중에 필요한 헤더가 누락된 경우에는 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤, 
// true를 반환한다.
// SIP BYE 요청은 SIP 통화 종료 관리에 중요한 역할을 하므로, 
// SIP 통화 흐름을 올바르게 관리하기 위해 필요한 처리를 수행한 후에는 true를 반환한다.
bool SipCore::handleBye(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse)
{
    std::string callId = sanitizeHeaderValue(getHeader(msg, "call-id"));

    if (callId.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    bool found = false;
    bool isSecondBye = false;  // cross-BYE (상대편도 BYE 보냄)
    bool isSameDirRetransmit = false; // 같은 방향 BYE 재전송 (UDP)
    std::string fwdIp;
    uint16_t fwdPort = 0;
    TransportType fwdTransport = TransportType::UDP;
    std::string fwdContactUri;  // 상대방의 Contact URI (Request-URI 재작성용)
    {
        // 올바른 뮤텍스 순서로 동시에 잠금
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        // Dialog에서 상대방 정보 조회 (BYE를 전달할 대상)
        auto dit = dialogs_.find(callId);
        if (dit != dialogs_.end())
        {
            DialogPeerSide side = classifyDialogPeerSide(dit->second, nullptr, msg, pkt);
            if (side == DialogPeerSide::Caller)
            {
                found = true;
                // caller가 BYE 보냄 → callee에게 전달
                fwdIp = dit->second.calleeIp;
                fwdPort = dit->second.calleePort;
                fwdTransport = dit->second.calleeTransport;
                fwdContactUri = dit->second.remoteTarget;  // callee의 Contact URI
            }
            else if (side == DialogPeerSide::Callee)
            {
                found = true;
                // callee가 BYE 보냄 → caller에게 전달
                fwdIp = dit->second.callerIp;
                fwdPort = dit->second.callerPort;
                fwdTransport = dit->second.callerTransport;
                fwdContactUri = dit->second.callerContact; // caller의 Contact URI
            }

            if (found && dit->second.byeReceived)
            {
                // 이전 BYE와 같은 발신자인지 확인
                if (pkt.remoteIp == dit->second.byeSenderIp &&
                    pkt.remotePort == dit->second.byeSenderPort)
                {
                    // 같은 방향 재전송 (UDP 손실 대비) → Dialog/ActiveCall 유지
                    isSameDirRetransmit = true;
                }
                else
                {
                    // cross-BYE (상대편도 BYE 보냄) → Dialog 삭제
                    isSecondBye = true;
                    dialogs_.erase(dit);
                }
            }
            else if (found)
            {
                // 첫 번째 BYE → 삭제하지 않고 표시만
                dit->second.byeReceived = true;
                dit->second.byeSenderIp = pkt.remoteIp;
                dit->second.byeSenderPort = pkt.remotePort;
            }
        }

        // ActiveCall에서도 상대방 정보 조회 (Dialog가 없는 경우)
        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            if (!found)
            {
                DialogPeerSide side = classifyDialogPeerSide(it->second, msg, pkt);
                if (side == DialogPeerSide::Caller)
                {
                    found = true;
                    fwdIp = it->second.calleeIp;
                    fwdPort = it->second.calleePort;
                    fwdTransport = it->second.calleeTransport;
                }
                else if (side == DialogPeerSide::Callee)
                {
                    found = true;
                    fwdIp = it->second.callerIp;
                    fwdPort = it->second.callerPort;
                    fwdTransport = it->second.callerTransport;
                }
            }

            if (isSameDirRetransmit)
            {
                // 같은 방향 재전송 → ActiveCall 유지 (삭제하지 않음)
            }
            else if (it->second.byeReceived)
            {
                if (pkt.remoteIp == it->second.byeSenderIp &&
                    pkt.remotePort == it->second.byeSenderPort)
                {
                    // ActiveCall에서도 같은 방향 재전송 감지 → 유지
                    isSameDirRetransmit = true;
                }
                else
                {
                    // cross-BYE → ActiveCall 삭제
                    activeCalls_.erase(it);
                }
            }
            else if (isSecondBye)
            {
                // Dialog에서 cross-BYE 감지됨 → ActiveCall 삭제
                activeCalls_.erase(it);
            }
            else
            {
                // 첫 번째 BYE → 삭제하지 않고 표시만
                it->second.byeReceived = true;
                it->second.byeSenderIp = pkt.remoteIp;
                it->second.byeSenderPort = pkt.remotePort;
            }
        }

        // PendingInvite 정리 (BYE 수신 시 항상)
        for (auto pit = pendingInvites_.begin(); pit != pendingInvites_.end(); )
        {
            if (pit->first.rfind(callId + ":", 0) == 0)
            {
                pit = pendingInvites_.erase(pit);   
            }
            else
            {
                ++pit;
            }
        }
    }

    // SIP BYE 요청이 올바르게 처리된 경우에는 200 OK 응답을 생성하여 outResponse에 반환한다.
    if (found)
    {
        outResponse = buildSimpleResponse(msg, 200, "OK");

        // BYE를 상대방에게 전달 (B2BUA/프록시 동작)
        if (sender_ && !fwdIp.empty())
        {
            // BYE에 프록시 Via 추가, Max-Forwards 감소, Route 제거 후 전달
            std::string fwdBye = addProxyVia(pkt.data, pkt.transport);
            fwdBye = decrementMaxForwards(fwdBye);
            fwdBye = stripOwnRoute(fwdBye, pkt.transport);

            // RFC 3261 §16.6: Request-URI를 상대방의 Contact URI로 재작성
            // 원래 BYE의 Request-URI가 상대방의 실제 Contact과 다를 수 있으므로
            // Dialog에 저장된 Contact URI로 재작성하여 정확한 라우팅 보장
            if (!fwdContactUri.empty())
            {
                fwdBye = rewriteRequestUri(fwdBye, fwdContactUri);
            }

            Logger::instance().info("[handleBye] Forwarding BYE: callId=" + callId
                + " to=" + fwdIp + ":" + std::to_string(fwdPort)
                + " contactUri=" + (fwdContactUri.empty() ? "(none)" : fwdContactUri));

            sender_(fwdIp, fwdPort, fwdBye, fwdTransport);
        }
    }
    else
    {
        // SIP BYE 요청이 처리되지 않은 경우에는 481 Call/Transaction Does Not Exist 응답을 생성하여 outResponse에 반환한다.
        outResponse = buildSimpleResponse(msg, 481, "Call/Transaction Does Not Exist");
    }

    return true;
}

// SIP CANCEL 요청 처리 함수인 handleCancel는 SIP 통화 취소 관리를 수행한다.
// SIP CANCEL 요청 메시지에서 Call-ID 헤더와 CSeq 헤더를 추출하여 SIP 통화 흐름을 관리하며, 
// SIP CANCEL 요청 처리 중에는 Dialog에서 상대방 정보 조회, ActiveCall에서 상대방 정보 조회, pendingInvites_ 정리 등의 처리가 수행된다.
// SIP CANCEL 요청 처리 후, 필요한 경우 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환할 수 있도록 구현되어 있으며,
// SIP CANCEL 요청이 올바르게 처리된 경우에는 true를 반환한다. 
// SIP CANCEL 요청 처리 중에 필요한 헤더가 누락된 경우에는 400 Bad Request 응답을 생성하여 outResponse에 반환한 뒤, true를 반환한다.
bool SipCore::handleCancel(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    (void)pkt;

    std::string callId = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string cseqHdr = sanitizeHeaderValue(getHeader(msg, "cseq"));

    if (callId.empty() || cseqHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    std::string key = callId + ":" + std::to_string(cseqNum);

    // Collect data under locks (correct order: callMutex_ -> pendingInvMutex_ -> dlgMutex_)
    std::string calleeIp;
    uint16_t calleePort = 0;
    TransportType calleeTransport = TransportType::UDP;
    std::string cancelRaw;
    bool foundPending = false;

    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto pit = pendingInvites_.find(key);
        if (pit != pendingInvites_.end())
        {
            // RFC 3261 §9.2: 매칭 트랜잭션 존재 → 200 OK
            outResponse = buildSimpleResponse(msg, 200, "OK");

            if (pit->second.state == TxState::COMPLETED)
            {
                // RFC 3261 §9.2: 이미 최종 응답을 받은 트랜잭션 — CANCEL 효과 없음
                // 200 OK 응답만 하고 CANCEL을 callee에게 전달하지 않음
                Logger::instance().info("[handleCancel] INVITE already COMPLETED, "
                    "CANCEL has no effect: key=" + key);
            }
            else
            {
                foundPending = true;

                // PendingInvite에서 callee 정보 가져오기
                calleeIp = pit->second.calleeIp;
                calleePort = pit->second.calleePort;
                calleeTransport = pit->second.calleeTransport;

                // callee에게 전달할 CANCEL 생성
                cancelRaw = buildCancelForPending(pit->second);

                // pendingInvite를 삭제하지 않음 — callee의 487 응답이 handleResponse를 통해
                // 정상적으로 처리되도록 함 (caller에게 487 전달 + callee에게 ACK)
                // RFC 3261 §16.10: 프록시는 CANCEL을 전달하고, callee의 응답을 그대로 caller에게 전달해야 함
            }
        }
        else
        {
            // RFC 3261 §9.2: 매칭 트랜잭션 없음 → 481
            outResponse = buildSimpleResponse(msg, 481, "Call/Transaction Does Not Exist");

            // UDP 재정렬로 INVITE보다 CANCEL이 먼저 도착할 수 있으므로
            // 보류 CANCEL 목록에 등록하여, INVITE가 PendingInvite를 생성할 때 즉시 취소 처리하도록 함
            pendingCancels_.insert(key);
            Logger::instance().info("[handleCancel] No matching transaction: key=" + key);

            // 미확립 ActiveCall이 이미 존재하면 정리
            auto acIt = activeCalls_.find(callId);
            if (acIt != activeCalls_.end() && !acIt->second.confirmed)
            {
                activeCalls_.erase(acIt);
            }
        }
    } // locks released

    // Send outside locks
    if (foundPending && sender_)
    {
        if (!cancelRaw.empty() && !calleeIp.empty())
        {
            // callee에게 CANCEL 전달
            sender_(calleeIp, calleePort, cancelRaw, calleeTransport);
            Logger::instance().info("[handleCancel] CANCEL forwarded to callee: "
                + calleeIp + ":" + std::to_string(calleePort) + " key=" + key);
        }
        else
        {
            Logger::instance().info("[handleCancel] CANCEL not sent: cancelRaw.empty="
                + std::to_string(cancelRaw.empty()) + " calleeIp.empty="
                + std::to_string(calleeIp.empty()) + " key=" + key);
        }
        // 487은 프록시가 직접 생성하지 않음 —
        // callee의 487 응답이 handleResponse를 통해 자연스럽게 caller에게 전달됨
    }

    return true;
}

// SIP OPTIONS 요청 처리 함수인 handleOptions는 SIP 기능 탐색 관리를 수행한다.
// SIP OPTIONS 요청 메시지에서 필요한 헤더를 추출하여 SIP 기능 탐색 흐름을 관리하며, 
// SIP OPTIONS 요청 처리 중에는 적절한 SIP 응답 메시지를 생성하여 outResponse에 반환한다.
// SIP OPTIONS 요청 처리 후, SIP 기능 탐색 흐름을 올바르게 관리하기 위해 필요한 처리를 수행한 후에는 true를 반환한다. 
// SIP OPTIONS 요청 처리 중에 필요한 헤더가 누락된 경우에도 SIP OPTIONS 요청은 SIP 기능 탐색에 중요한 역할을 하므로, 
// SIP 기능 탐색 흐름을 올바르게 관리하기 위해 필요한 처리를 수행한 후에는 true를 반환한다.
bool SipCore::handleOptions(const UdpPacket& pkt,
                            const SipMessage& msg,
                            std::string& outResponse)
{
    (void)pkt;

    std::ostringstream oss;
    oss << "SIP/2.0 200 OK\r\n";

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

    oss << "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER, MESSAGE, SUBSCRIBE, NOTIFY\r\n";
    oss << "Accept: application/sdp\r\n";
    oss << "Server: SIPLite/0.1\r\n";
    oss << "Content-Length: 0\r\n";
    oss << "\r\n";

    outResponse = oss.str();
    return true;
}

// ================================
// SIP MESSAGE 요청 처리 (RFC 3428)
// ================================
// SIP MESSAGE는 인스턴트 메시징을 위한 메서드로, 프록시는 수신자의 등록 정보를
// 조회하여 메시지를 전달한다. In-dialog MESSAGE의 경우 기존 Dialog를 통해 상대방에게 전달한다.
bool SipCore::handleMessage(const UdpPacket& pkt,
                            const SipMessage& msg,
                            std::string& outResponse)
{
    std::string toHdr   = sanitizeHeaderValue(getHeader(msg, "to"));
    std::string fromHdr = sanitizeHeaderValue(getHeader(msg, "from"));
    std::string callId  = sanitizeHeaderValue(getHeader(msg, "call-id"));

    if (toHdr.empty() || fromHdr.empty() || callId.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // ===== In-dialog MESSAGE: 기존 Dialog가 있으면 상대방에게 전달 =====
    {
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);
        auto dit = dialogs_.find(callId);
        if (dit != dialogs_.end() && dit->second.confirmed)
        {
            std::string fwdIp;
            uint16_t fwdPort = 0;
            TransportType fwdTransport = TransportType::UDP;
            std::string fwdContactUri;
            DialogPeerSide side = classifyDialogPeerSide(dit->second, nullptr, msg, pkt);
            if (side == DialogPeerSide::Caller)
            {
                fwdIp = dit->second.calleeIp;
                fwdPort = dit->second.calleePort;
                fwdTransport = dit->second.calleeTransport;
                fwdContactUri = dit->second.remoteTarget;
            }
            else if (side == DialogPeerSide::Callee)
            {
                fwdIp = dit->second.callerIp;
                fwdPort = dit->second.callerPort;
                fwdTransport = dit->second.callerTransport;
                fwdContactUri = dit->second.callerContact;
            }

            // Dialog 락 해제 후 네트워크 전송은 아래에서 수행
            if (!fwdIp.empty() && sender_)
            {
                std::string fwdMsg = addProxyVia(pkt.data, pkt.transport);
                fwdMsg = decrementMaxForwards(fwdMsg);
                fwdMsg = stripOwnRoute(fwdMsg, pkt.transport);
                if (!fwdContactUri.empty())
                {
                    fwdMsg = rewriteRequestUri(fwdMsg, fwdContactUri);
                }

                sender_(fwdIp, fwdPort, fwdMsg, fwdTransport);

                Logger::instance().info("[handleMessage] In-dialog MESSAGE forwarded: callId=" + callId
                    + " to=" + fwdIp + ":" + std::to_string(fwdPort));
            }

            outResponse = buildSimpleResponse(msg, 200, "OK");
            return true;
        }
    }

    // ===== Out-of-dialog MESSAGE: 등록 정보에서 수신자 조회 =====
    std::string toUri = extractUriFromHeader(toHdr);

    Registration regCopy;
    bool found = false;
    bool knownButOffline = false;

    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = findByUser_(toUri);
        if (it != regs_.end())
        {
            if (it->second.expiresAt > std::chrono::steady_clock::now()
                && it->second.loggedIn)
            {
                regCopy = it->second;
                found = true;
            }
            else if (it->second.isStatic)
            {
                knownButOffline = true;
            }
        }
    }

    if (!found)
    {
        if (knownButOffline)
        {
            outResponse = buildSimpleResponse(msg, 480, "Temporarily Unavailable");
        }
        else
        {
            outResponse = buildSimpleResponse(msg, 404, "Not Found");
        }
        return true;
    }

    // 수신자에게 MESSAGE 전달
    std::string contactUri = extractUriFromHeader(regCopy.contact);
    std::string fwdMsg = addProxyVia(pkt.data, pkt.transport);
    fwdMsg = decrementMaxForwards(fwdMsg);
    if (!contactUri.empty())
    {
        fwdMsg = rewriteRequestUri(fwdMsg, contactUri);
    }

    if (sender_)
    {
        sender_(regCopy.ip, regCopy.port, fwdMsg, regCopy.transport);
    }

    outResponse = buildSimpleResponse(msg, 200, "OK");

    Logger::instance().info("[handleMessage] Forwarded MESSAGE: callId=" + callId
        + " from=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort)
        + " to=" + regCopy.ip + ":" + std::to_string(regCopy.port));

    return true;
}

// ================================
// SIP SUBSCRIBE 요청 처리 (RFC 6665)
// ================================
// SUBSCRIBE는 이벤트 구독을 위한 메서드로, 서버는 구독 상태를 저장하고
// 초기 NOTIFY를 전송한 후 200 OK를 반환한다.
// Expires: 0은 구독 해지를 의미한다.
bool SipCore::handleSubscribe(const UdpPacket& pkt,
                              const SipMessage& msg,
                              std::string& outResponse)
{
    std::string toHdr     = sanitizeHeaderValue(getHeader(msg, "to"));
    std::string fromHdr   = sanitizeHeaderValue(getHeader(msg, "from"));
    std::string callId    = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string cseqHdr   = sanitizeHeaderValue(getHeader(msg, "cseq"));
    std::string eventHdr  = sanitizeHeaderValue(getHeader(msg, "event"));

    if (toHdr.empty() || fromHdr.empty() || callId.empty() || cseqHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // RFC 6665 §3.1.1: Event 헤더는 SUBSCRIBE에 필수
    if (eventHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 489, "Bad Event");
        return true;
    }

    // 지원하는 이벤트 패키지 확인 (presence, dialog, message-summary)
    std::string eventLower = toLower(trim(eventHdr));
    // event 파라미터 제거 (예: "presence;id=1" → "presence")
    auto semiPos = eventLower.find(';');
    std::string eventPackage = (semiPos != std::string::npos)
        ? trim(eventLower.substr(0, semiPos)) : eventLower;

    static const std::unordered_set<std::string> supportedEvents = {
        "presence", "dialog", "message-summary"
    };
    if (supportedEvents.find(eventPackage) == supportedEvents.end())
    {
        outResponse = buildSimpleResponse(msg, 489, "Bad Event");
        return true;
    }

    // Expires 처리
    std::string expiresHdr = sanitizeHeaderValue(getHeader(msg, "expires"));
    int expiresSec = SipConstants::DEFAULT_SUB_EXPIRES_SEC;
    if (!expiresHdr.empty())
    {
        std::string trimmed = trim(expiresHdr);
        int val = -1;
        auto [ptr, ec] = std::from_chars(
            trimmed.data(), trimmed.data() + trimmed.size(), val);
        if (ec != std::errc{} || ptr != trimmed.data() + trimmed.size() || val < 0)
        {
            outResponse = buildSimpleResponse(msg, 400, "Bad Request - Invalid Expires");
            return true;
        }
        expiresSec = val;
    }
    if (expiresSec > SipConstants::MAX_SUB_EXPIRES_SEC)
    {
        expiresSec = SipConstants::MAX_SUB_EXPIRES_SEC;
    }

    std::string fromUri = extractUriFromHeader(fromHdr);
    std::string toUri   = extractUriFromHeader(toHdr);
    std::string fromTag = extractTagFromHeader(fromHdr);

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // Contact 추출 (구독자의 NOTIFY 수신 주소)
    std::string contactHdr = sanitizeHeaderValue(getHeader(msg, "contact"));
    std::string contactUri = extractUriFromHeader(contactHdr);

    // Expires: 0 = 구독 해지
    if (expiresSec == 0)
    {
        std::string notifyMsg;
        {
            std::lock_guard<std::mutex> lock(subMutex_);
            auto it = subscriptions_.find(callId);
            if (it != subscriptions_.end())
            {
                it->second.state = Subscription::State::TERMINATED;
                notifyMsg = buildNotifyUnlocked_(callId, "terminated;reason=deactivated");
                subscriptions_.erase(it);
            }
            else
            {
                // 존재하지 않는 구독의 해지 — 응답은 보내되 NOTIFY는 건너뜀
            }
        }

        // NOTIFY(terminated) 전송
        if (sender_ && !notifyMsg.empty())
        {
            sender_(pkt.remoteIp, pkt.remotePort, notifyMsg, pkt.transport);
        }

        // 200 OK with Expires: 0
        std::ostringstream oss;
        oss << "SIP/2.0 200 OK\r\n";
        std::string via = sanitizeHeaderValue(getHeader(msg, "via"));
        if (!via.empty()) oss << "Via: " << via << "\r\n";
        oss << "From: " << fromHdr << "\r\n";
        oss << "To: " << ensureToTag(toHdr) << "\r\n";
        oss << "Call-ID: " << callId << "\r\n";
        oss << "CSeq: " << cseqHdr << "\r\n";
        oss << "Expires: 0\r\n";
        oss << "Server: SIPLite/0.1\r\n";
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";
        outResponse = oss.str();

        Logger::instance().info("[handleSubscribe] Unsubscribed: callId=" + callId
            + " event=" + eventPackage);
        return true;
    }

    // 새 구독 또는 갱신
    std::string toTag;
    {
        std::lock_guard<std::mutex> lock(subMutex_);

        auto it = subscriptions_.find(callId);
        if (it != subscriptions_.end())
        {
            // 기존 구독 갱신 (refresh)
            it->second.subscriberIp = pkt.remoteIp;
            it->second.subscriberPort = pkt.remotePort;
            it->second.subscriberTransport = pkt.transport;
            it->second.contact = contactUri;
            it->second.expiresAt = std::chrono::steady_clock::now()
                + std::chrono::seconds(expiresSec);
            it->second.cseq = cseqNum;
            it->second.state = Subscription::State::ACTIVE;
            toTag = it->second.toTag;
        }
        else
        {
            // 새 구독 생성
            if (subscriptions_.size() >= SipConstants::MAX_SUBSCRIPTIONS)
            {
                outResponse = buildSimpleResponse(msg, 503, "Service Unavailable");
                return true;
            }

            Subscription sub;
            sub.subscriberAor = fromUri;
            sub.targetAor = toUri;
            sub.event = eventPackage;
            sub.callId = callId;
            sub.fromTag = fromTag;
            sub.toTag = generateTag();
            sub.subscriberIp = pkt.remoteIp;
            sub.subscriberPort = pkt.remotePort;
            sub.subscriberTransport = pkt.transport;
            sub.contact = contactUri;
            sub.cseq = cseqNum;
            sub.expiresAt = std::chrono::steady_clock::now()
                + std::chrono::seconds(expiresSec);
            sub.state = Subscription::State::ACTIVE;
            toTag = sub.toTag;
            subscriptions_[callId] = std::move(sub);
        }
    }

    // 200 OK with Expires
    {
        std::ostringstream oss;
        oss << "SIP/2.0 200 OK\r\n";
        std::string via = sanitizeHeaderValue(getHeader(msg, "via"));
        if (!via.empty()) oss << "Via: " << via << "\r\n";
        oss << "From: " << fromHdr << "\r\n";
        // To 태그 추가
        {
            std::string toWithTag = toHdr;
            std::string existingTag = extractTagFromHeader(toHdr);
            if (existingTag.empty())
            {
                toWithTag += ";tag=" + toTag;
            }
            oss << "To: " << toWithTag << "\r\n";
        }
        oss << "Call-ID: " << callId << "\r\n";
        oss << "CSeq: " << cseqHdr << "\r\n";
        oss << "Expires: " << expiresSec << "\r\n";
        oss << "Server: SIPLite/0.1\r\n";
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";
        outResponse = oss.str();
    }

    // initial NOTIFY 전송 (RFC 6665 §4.4.1: SUBSCRIBE에 대한 즉시 NOTIFY)
    if (sender_)
    {
        std::string notifyMsg = buildNotify(callId, "active");
        sender_(pkt.remoteIp, pkt.remotePort, notifyMsg, pkt.transport);
    }

    Logger::instance().info("[handleSubscribe] Subscribed: callId=" + callId
        + " event=" + eventPackage + " subscriber=" + fromUri
        + " target=" + toUri + " expires=" + std::to_string(expiresSec));

    return true;
}

// ================================
// SIP NOTIFY 요청 처리 (RFC 6665)
// ================================
// 단말이 보내는 NOTIFY를 수신하거나, 프록시로서 전달한다.
bool SipCore::handleNotify(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    std::string toHdr   = sanitizeHeaderValue(getHeader(msg, "to"));
    std::string fromHdr = sanitizeHeaderValue(getHeader(msg, "from"));
    std::string callId  = sanitizeHeaderValue(getHeader(msg, "call-id"));
    std::string eventHdr = sanitizeHeaderValue(getHeader(msg, "event"));
    std::string subStateHdr = sanitizeHeaderValue(getHeader(msg, "subscription-state"));

    if (toHdr.empty() || fromHdr.empty() || callId.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    // RFC 6665 §3.2.2: Event 헤더는 NOTIFY에 필수
    if (eventHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 489, "Bad Event");
        return true;
    }

    // Subscription-State 헤더 확인 (RFC 6665 §4.1.3: NOTIFY에 필수)
    if (subStateHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request - Missing Subscription-State");
        return true;
    }

    // 해당 구독이 존재하는지 확인
    bool subFound = false;
    std::string subscriberIp;
    uint16_t subscriberPort = 0;
    TransportType subscriberTransport = TransportType::UDP;
    {
        std::lock_guard<std::mutex> lock(subMutex_);
        auto it = subscriptions_.find(callId);
        if (it != subscriptions_.end())
        {
            subFound = true;
            subscriberIp = it->second.subscriberIp;
            subscriberPort = it->second.subscriberPort;
            subscriberTransport = it->second.subscriberTransport;

            // Subscription-State 처리
            std::string stateLower = toLower(trim(subStateHdr));
            if (stateLower.find("terminated") == 0)
            {
                it->second.state = Subscription::State::TERMINATED;
                subscriptions_.erase(it);
            }
        }
    }

    if (!subFound)
    {
        // RFC 6665 §4.1.3: 구독이 없으면 481 응답
        outResponse = buildSimpleResponse(msg, 481, "Subscription Does Not Exist");
        return true;
    }

    // NOTIFY를 구독자에게 전달 (프록시 동작)
    // 단말이 NOTIFY를 보내는 경우: 예를 들어 notifier → proxy → subscriber
    // 단, 서버 자체가 notifier인 경우는 outResponse로 200 OK 반환
    if (sender_ && !subscriberIp.empty()
        && (pkt.remoteIp != subscriberIp || pkt.remotePort != subscriberPort))
    {
        // notifier에서 온 NOTIFY를 subscriber에게 전달
        std::string fwdNotify = addProxyVia(pkt.data, pkt.transport);
        fwdNotify = decrementMaxForwards(fwdNotify);
        sender_(subscriberIp, subscriberPort, fwdNotify, subscriberTransport);

        Logger::instance().info("[handleNotify] Forwarded NOTIFY: callId=" + callId
            + " to=" + subscriberIp + ":" + std::to_string(subscriberPort));
    }

    outResponse = buildSimpleResponse(msg, 200, "OK");
    return true;
}

// ================================
// NOTIFY 메시지 빌더
// ================================
std::string SipCore::buildNotify(const std::string& subKey,
                                  const std::string& subState,
                                  const std::string& body,
                                  const std::string& contentType) const
{
    std::lock_guard<std::mutex> lock(subMutex_);
    return buildNotifyUnlocked_(subKey, subState, body, contentType);
}

std::string SipCore::buildNotifyUnlocked_(const std::string& subKey,
                                           const std::string& subState,
                                           const std::string& body,
                                           const std::string& contentType) const
{
    auto it = subscriptions_.find(subKey);
    if (it == subscriptions_.end())
        return "";

    const auto& sub = it->second;
    int notifyCSeq = sub.cseq + 1;

    std::ostringstream oss;
    std::string targetUri = sub.contact.empty() ? sub.subscriberAor : sub.contact;
    oss << "NOTIFY " << targetUri << " SIP/2.0\r\n";
    oss << "Via: SIP/2.0/UDP " << udpLocal_.ip << ":" << udpLocal_.port
        << ";branch=z9hG4bK-notify-" << subKey << "-" << notifyCSeq << "\r\n";
    oss << "From: <" << sub.targetAor << ">;tag=" << sub.toTag << "\r\n";
    oss << "To: <" << sub.subscriberAor << ">;tag=" << sub.fromTag << "\r\n";
    oss << "Call-ID: " << sub.callId << "\r\n";
    oss << "CSeq: " << notifyCSeq << " NOTIFY\r\n";
    oss << "Event: " << sub.event << "\r\n";
    oss << "Subscription-State: " << subState << "\r\n";
    oss << "Max-Forwards: 70\r\n";
    oss << "Server: SIPLite/0.1\r\n";

    if (!body.empty() && !contentType.empty())
    {
        oss << "Content-Type: " << contentType << "\r\n";
        oss << "Content-Length: " << body.size() << "\r\n";
        oss << "\r\n";
        oss << body;
    }
    else
    {
        oss << "Content-Length: 0\r\n";
        oss << "\r\n";
    }

    return oss.str();
}

// Helper function to extract tag parameter from a SIP header value
// SIP 헤더 값에서 tag 파라미터를 추출하는 헬퍼 함수인 extractTagFromHeader는 SIP 메시지에서 tag 정보를 추출하여 SIP 흐름 관리에 활용한다.
// SIP 헤더 값에서 tag 파라미터를 추출하는 과정에서, 헤더 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 빈 문자열을 반환하여 SIP 흐름 관리에 반영한다.
// "tag=" 문자열을 대소문자 구분 없이 검색하여 tag 값을 추출한다. 
// tag 값이 최대 허용 크기를 초과하는 경우에는 빈 문자열을 반환하여 SIP 흐름 관리에 반영한다.
// tag 값이 세미콜론, 쉼표, 공백, 줄바꿈 문자 등으로 구분되어 있는 경우에는 해당 구분자까지의 문자열을 tag 값으로 추출한다.
std::string SipCore::extractTagFromHeader(const std::string& header) const
{
    if (header.empty() || header.size() > SipConstants::MAX_HEADER_SIZE)
    {
        return "";
    }

    // Case-insensitive search for "tag=" (#14 fix)
    std::string lowerHeader = toLower(header);
    std::size_t tagPos = lowerHeader.find("tag=");
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

    if (tag.size() > 128)
    {
        return "";
    }

    return tag;
}

// Helper function to generate a random tag value
// SIP 메시지에서 tag 값을 생성하는 헬퍼 함수인 generateTag는 SIP 흐름 관리에 필요한 고유한 tag 값을 생성한다.
// C++11의 <random> 라이브러리를 사용하여 고유한 tag 값을 생성한다. 
// thread_local로 선언된 std::mt19937_64 난수 생성기를 사용하여, 각 스레드마다 독립적인 난수 시퀀스를 생성한다. 
// std::uniform_int_distribution을 사용하여 64비트 범위의 난수를 생성한다. 
// 생성된 난수를 16진수 문자열로 변환하여 반환한다.
std::string SipCore::generateTag() const
{
    static thread_local std::mt19937_64 gen([]() -> std::mt19937_64::result_type {
        std::random_device rd;
        try 
        {
            // Combine two 32-bit values for a 64-bit seed
            uint64_t hi = static_cast<uint64_t>(rd()) << 32;
            uint64_t lo = static_cast<uint64_t>(rd());
            return static_cast<std::mt19937_64::result_type>(hi | lo);
        } 
        catch (...) 
        {
            auto seed = static_cast<std::mt19937_64::result_type>(
                std::chrono::steady_clock::now().time_since_epoch().count() ^
                std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return seed;
        }
    }());

    static thread_local std::uniform_int_distribution<uint64_t> dis(
        0, std::numeric_limits<uint64_t>::max());

    std::ostringstream oss;
    oss << std::hex << dis(gen);
    return oss.str();
}

// Request-URI 재작성 (RFC 3261 §16.6 step 6)
// 프록시가 INVITE를 callee에게 전달할 때, Request-URI를 callee의 Contact 주소로 변경
// 예: "INVITE sip:1001@proxy SIP/2.0" → "INVITE sip:1001@callee:5060 SIP/2.0"
std::string SipCore::rewriteRequestUri(const std::string& rawMsg, const std::string& newUri) const
{
    if (newUri.empty()) return rawMsg;

    // request-line: METHOD SP Request-URI SP SIP-Version CRLF
    auto lineEnd = rawMsg.find("\r\n");
    if (lineEnd == std::string::npos) return rawMsg;

    std::string requestLine = rawMsg.substr(0, lineEnd);

    // 첫 번째 공백 (METHOD 뒤)
    auto sp1 = requestLine.find(' ');
    if (sp1 == std::string::npos) return rawMsg;

    // 두 번째 공백 (Request-URI 뒤)
    auto sp2 = requestLine.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return rawMsg;

    std::string method = requestLine.substr(0, sp1);
    std::string version = requestLine.substr(sp2 + 1);

    std::string newRequestLine = method + " " + newUri + " " + version;

    std::string result;
    result.reserve(newRequestLine.size() + 2 + rawMsg.size() - lineEnd);
    result.append(newRequestLine);
    result.append(rawMsg, lineEnd);  // CRLF + 나머지 헤더 + 바디
    return result;
}

// Max-Forwards 감소 (RFC 3261 §16.6 step 3)
// 프록시가 요청을 전달할 때 Max-Forwards 값을 1 감소시킨다.
// 헤더가 없으면 Max-Forwards: 70을 삽입한다.
std::string SipCore::decrementMaxForwards(const std::string& rawMsg) const
{
    // 헤더 영역에서 Max-Forwards 탐색 (대소문자 무시)
    std::string lower = rawMsg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::string needle = "\r\nmax-forwards:";
    auto pos = lower.find(needle);
    if (pos != std::string::npos)
    {
        // 값 시작 위치
        size_t valStart = pos + needle.size();
        // 공백 건너뛰기
        while (valStart < rawMsg.size() && rawMsg[valStart] == ' ') ++valStart;
        // 값 끝 위치
        size_t valEnd = valStart;
        while (valEnd < rawMsg.size() && rawMsg[valEnd] >= '0' && rawMsg[valEnd] <= '9') ++valEnd;

        if (valEnd > valStart)
        {
            int val = 0;
            auto [ptr, ec] = std::from_chars(rawMsg.data() + valStart, rawMsg.data() + valEnd, val);
            if (ec == std::errc())
            {
                int newVal = (val > 0) ? val - 1 : 0;
                std::string result;
                result.reserve(rawMsg.size() + 4);
                result.append(rawMsg, 0, valStart);
                result.append(std::to_string(newVal));
                result.append(rawMsg, valEnd);
                return result;
            }
        }
    }

    // Max-Forwards 헤더 없음 → 기본값 70 삽입 (request-line 직후)
    auto crlfPos = rawMsg.find("\r\n");
    if (crlfPos == std::string::npos) return rawMsg;

    std::string result;
    result.reserve(rawMsg.size() + 24);
    result.append(rawMsg, 0, crlfPos + 2);
    result.append("Max-Forwards: 70\r\n");
    result.append(rawMsg, crlfPos + 2);
    return result;
}

// 프록시 Via 헤더 추가 (RFC 3261 §16.6)
// INVITE를 callee에게 전달할 때, 프록시 자신의 Via를 최상단에 삽입하여
// callee의 응답이 반드시 프록시를 경유하도록 보장한다.
std::string SipCore::addProxyVia(const std::string& rawMsg,
                                 TransportType transport) const
{
    auto pos = rawMsg.find("\r\n");
    if (pos == std::string::npos) return rawMsg;

    std::string branch = "z9hG4bK-proxy-" + generateTag();
    const TransportLocalAddress* local = &udpLocal_;
    if (transport == TransportType::TCP)
    {
        local = &tcpLocal_;
    }
    else if (transport == TransportType::TLS)
    {
        local = &tlsLocal_;
    }

    std::string addr = local->ip.empty() ? "127.0.0.1" : local->ip;
    uint16_t port = local->port ? local->port : 5060;

    std::string via = std::string("Via: SIP/2.0/") + transportToken(transport) + " "
                    + addr + ":" + std::to_string(port)
                    + ";branch=" + branch + ";rport";

    std::string result;
    result.reserve(rawMsg.size() + via.size() + 4);
    result.append(rawMsg, 0, pos + 2);  // request-line + \r\n
    result.append(via);
    result.append("\r\n");
    result.append(rawMsg, pos + 2);     // 나머지 헤더 + 바디
    return result;
}

// 프록시 Via 헤더 제거 (RFC 3261 §16.7)
// callee의 응답을 caller에게 전달할 때, 프록시가 추가한 최상단 Via를 제거한다.
std::string SipCore::removeTopVia(const std::string& rawMsg) const
{
    // status-line 끝 위치
    auto firstLineEnd = rawMsg.find("\r\n");
    if (firstLineEnd == std::string::npos) return rawMsg;

    // 첫 번째 Via 헤더 찾기
    std::string afterFirstLine = rawMsg.substr(firstLineEnd + 2);
    std::string lowerHeaders = afterFirstLine;
    std::transform(lowerHeaders.begin(), lowerHeaders.end(), lowerHeaders.begin(), ::tolower);

    auto viaPos = lowerHeaders.find("via:");
    if (viaPos == std::string::npos) return rawMsg;

    // Via 라인 끝 찾기
    auto viaLineEnd = afterFirstLine.find("\r\n", viaPos);
    if (viaLineEnd == std::string::npos) return rawMsg;

    // 프록시가 추가한 Via인지 확인 (branch에 "proxy-" 포함)
    std::string viaLine = afterFirstLine.substr(viaPos, viaLineEnd - viaPos);
    if (viaLine.find("z9hG4bK-proxy-") == std::string::npos)
    {
        return rawMsg;  // 프록시가 추가한 Via가 아니면 제거하지 않음
    }

    // Via 라인 제거
    std::string result;
    result.reserve(rawMsg.size());
    result.append(rawMsg, 0, firstLineEnd + 2);
    if (viaPos > 0) result.append(afterFirstLine, 0, viaPos);
    result.append(afterFirstLine, viaLineEnd + 2);
    return result;
}

// Record-Route 헤더 추가 (RFC 3261 §16.6 step 4)
// INVITE를 callee에게 전달할 때, 프록시의 Record-Route를 삽입하여
// 이후 in-dialog 요청(ACK, BYE, re-INVITE 등)이 반드시 프록시를 경유하도록 보장한다.
// Linphone 등 UA는 200 OK에 포함된 Record-Route를 Route Set으로 저장하여
// 이후 요청에 Route 헤더로 추가한다.
std::string SipCore::addRecordRoute(const std::string& rawMsg,
                                    TransportType transport) const
{
    auto pos = rawMsg.find("\r\n");
    if (pos == std::string::npos) return rawMsg;

    const TransportLocalAddress* local = &udpLocal_;
    if (transport == TransportType::TCP)
    {
        local = &tcpLocal_;
    }
    else if (transport == TransportType::TLS)
    {
        local = &tlsLocal_;
    }

    std::string addr = local->ip.empty() ? "127.0.0.1" : local->ip;
    uint16_t port = local->port ? local->port : 5060;

    // lr 파라미터: loose routing (RFC 3261 §16.6)
    std::string rr;
    if (transport == TransportType::TLS)
    {
        rr = "Record-Route: <sips:" + addr + ":" + std::to_string(port) + ";lr>\r\n";
    }
    else if (transport == TransportType::TCP)
    {
        rr = "Record-Route: <sip:" + addr + ":" + std::to_string(port) + ";transport=tcp;lr>\r\n";
    }
    else
    {
        rr = "Record-Route: <sip:" + addr + ":" + std::to_string(port) + ";lr>\r\n";
    }

    std::string result;
    result.reserve(rawMsg.size() + rr.size());
    result.append(rawMsg, 0, pos + 2);  // request-line + \r\n
    result.append(rr);
    result.append(rawMsg, pos + 2);     // 나머지 헤더 + 바디
    return result;
}

// 자신을 가리키는 Route 헤더 제거 (loose routing 처리, RFC 3261 §16.4)
// Linphone이 Route: <sip:proxy:port;lr>을 포함하여 보낸 ACK/BYE에서
// 프록시 자신을 가리키는 Route 헤더를 제거한 후 다음 홉으로 전달한다.
std::string SipCore::stripOwnRoute(const std::string& rawMsg,
                                   TransportType transport) const
{
    const TransportLocalAddress* local = &udpLocal_;
    if (transport == TransportType::TCP)
    {
        local = &tcpLocal_;
    }
    else if (transport == TransportType::TLS)
    {
        local = &tlsLocal_;
    }

    std::string addr = local->ip.empty() ? "127.0.0.1" : local->ip;
    uint16_t port = local->port ? local->port : 5060;
    std::string selfUri = addr + ":" + std::to_string(port);
    std::string selfSipRoute = "sip:" + selfUri;
    std::string selfSipsRoute = "sips:" + selfUri;

    // Route 헤더 검색 (대소문자 무시)
    std::string lower = toLower(rawMsg);
    std::size_t searchPos = 0;

    while (true)
    {
        std::size_t pos = lower.find("\r\nroute:", searchPos);
        if (pos == std::string::npos) break;

        pos += 2;  // \r\n 건너뛰기
        std::size_t lineEnd = rawMsg.find("\r\n", pos);
        if (lineEnd == std::string::npos) break;

        std::string line = rawMsg.substr(pos, lineEnd - pos);
        if (line.find(selfUri) != std::string::npos ||
            line.find(selfSipRoute) != std::string::npos ||
            line.find(selfSipsRoute) != std::string::npos)
        {
            // 이 Route 라인 제거
            std::string result;
            result.reserve(rawMsg.size());
            result.append(rawMsg, 0, pos);
            result.append(rawMsg, lineEnd + 2);
            return result;
        }

        searchPos = lineEnd + 2;
    }

    return rawMsg;
}

// Helper function to build SIP response for INVITE requests
// SIP INVITE 요청에 대한 SIP 응답 메시지를 생성하는 헬퍼 함수인 buildInviteResponse는 SIP INVITE 요청에 대한 적절한 SIP 응답 메시지를 생성하여 SIP 흐름 관리에 활용한다.
// SIP INVITE 요청에 대한 SIP 응답 메시지를 생성할 때, To 헤더에 tag 파라미터가 없는 경우에는 toTag 매개변수로 전달된 값을 tag 파라미터로 추가하여 SIP 흐름 관리에 반영한다.
// 200 OK 응답인 경우에는 Contact 헤더를 포함하여 SIP 흐름 관리에 반영한다.
// SIP INVITE 요청에 대한 SIP 응답 메시지를 생성한 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송할 수 있도록 구현되어 있다.
std::string SipCore::buildInviteResponse(const SipMessage& req,
                                         int code,
                                         const std::string& reason,
                                         const std::string& toTag,
                                         const std::string& sdpBody,
                                         const std::string& contentType)
{
    std::ostringstream oss;
    oss << "SIP/2.0 " << code << " " << reason << "\r\n";

    std::string via     = sanitizeHeaderValue(getHeader(req, "via"));
    std::string from    = sanitizeHeaderValue(getHeader(req, "from"));
    std::string to      = sanitizeHeaderValue(getHeader(req, "to"));
    std::string callId  = sanitizeHeaderValue(getHeader(req, "call-id"));
    std::string cseq    = sanitizeHeaderValue(getHeader(req, "cseq"));

    if (!via.empty())    oss << "Via: "     << via    << "\r\n";
    if (!from.empty())   oss << "From: "    << from   << "\r\n";

    if (!to.empty())
    {
        std::string toWithTag = to;
        if (toLower(to).find("tag=") == std::string::npos && !toTag.empty())
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

    if (code >= 200 && code < 300)
    {
        oss << "Contact: <sip:server@0.0.0.0:5060>\r\n";
    }

    oss << "Server: SIPLite/0.1\r\n";

    if (!sdpBody.empty())
    {
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

// Helper function to build ACK request for pending INVITE
// SIP INVITE 요청에 대한 ACK 요청 메시지를 생성하는 헬퍼 함수인 buildAckForPending는 SIP INVITE 요청에 대한 ACK 요청 메시지를 생성하여 SIP 흐름 관리에 활용한다.
// SIP INVITE 요청에 대한 ACK 요청 메시지를 생성할 때, 원본 요청 메시지와 응답 메시지에서 필요한 헤더를 추출하여 ACK 요청 메시지에 포함한다. 
// ACK 요청 메시지의 Request-URI는 원본 요청 메시지의 Request-URI를 사용하되, 유효하지 않은 경우에는 "sip:unknown"으로 설정하여 SIP 흐름 관리에 반영한다.
// ACK 요청 메시지의 Via 헤더는 원본 요청 메시지의 top Via 헤더를 사용하여 SIP 흐름 관리에 반영한다. 
// ACK 요청 메시지의 From 헤더는 원본 요청 메시지의 From 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 ACK 요청 메시지에서 From 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// ACK 요청 메시지의 To 헤더는 응답 메시지의 To 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 ACK 요청 메시지에서 To 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// ACK 요청 메시지의 Call-ID 헤더는 응답 메시지의 Call-ID 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 ACK 요청 메시지에서 Call-ID 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// ACK 요청 메시지의 CSeq 헤더는 응답 메시지의 CSeq 헤더에서 숫자 부분만 추출하여 정수로 변환한 값을 사용하되, CSeq 헤더가 비어있거나 최대 허용 크기를 초과하는 경우에는 ACK 요청 메시지에서 CSeq 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// SIP INVITE 요청에 대한 ACK 요청 메시지를 생성한 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 ACK 메시지를 전송할 수 있도록 구현되어 있다.
std::string SipCore::buildAckForPending(const PendingInvite& pi, const std::string& respRaw) const
{
    SipMessage req, resp;
    if (!parseSipMessage(pi.origRequest, req))
    {
        return std::string();
    }

    if (!parseSipMessage(respRaw, resp))
    {
        return std::string();
    }

    std::string requestUri = req.requestUri;
    if (!isValidRequestUri(requestUri))
    {
        requestUri = "sip:unknown";
    }

    std::string fromHdr     = sanitizeHeaderValue(getHeader(req, "from"));
    std::string toHdr       = sanitizeHeaderValue(getHeader(resp, "to"));
    std::string callId      = sanitizeHeaderValue(getHeader(resp, "call-id"));
    std::string cseq        = sanitizeHeaderValue(getHeader(resp, "cseq"));

    int cseqNum = parseCSeqNum(cseq);

    std::ostringstream oss;
    oss << "ACK " << requestUri << " SIP/2.0\r\n";

    // RFC 3261 §17.1.1.3: ACK의 Via는 원본 요청의 top Via만 사용
    // 파서가 여러 Via를 콤마로 결합하므로, 첫 번째(상단) Via만 추출
    std::string allVias = sanitizeHeaderValue(getHeader(req, "via"));
    std::string via;
    {
        auto commaPos = allVias.find(',');
        via = (commaPos != std::string::npos) ? allVias.substr(0, commaPos) : allVias;
        while (!via.empty() && via.back() == ' ') via.pop_back();
    }
    if (!via.empty()) oss << "Via: " << via << "\r\n";

    // Max-Forwards 추출 — RFC 3261 §8.1.1: 모든 SIP 요청에 필수
    std::string maxFwd = sanitizeHeaderValue(getHeader(req, "max-forwards"));
    if (maxFwd.empty()) maxFwd = "70";
    oss << "Max-Forwards: " << maxFwd << "\r\n";

    if (!fromHdr.empty()) oss << "From: " << fromHdr << "\r\n";
    if (!toHdr.empty())   oss << "To: " << toHdr << "\r\n";
    if (!callId.empty())  oss << "Call-ID: " << callId << "\r\n";

    oss << "CSeq: " << cseqNum << " ACK\r\n";
    oss << "Content-Length: 0\r\n\r\n";

    return oss.str();
}

// Helper function to build CANCEL request for pending INVITE
// SIP INVITE 요청에 대한 CANCEL 요청 메시지를 생성하는 헬퍼 함수인 buildCancelForPending는 SIP INVITE 요청에 대한 CANCEL 요청 메시지를 생성하여 SIP 흐름 관리에 활용한다.
// SIP INVITE 요청에 대한 CANCEL 요청 메시지를 생성할 때, 원본 요청 메시지에서 필요한 헤더를 추출하여 CANCEL 요청 메시지에 포함한다.
// CANCEL 요청 메시지의 Request-URI는 원본 요청 메시지의 Request-URI를 사용하되, 유효하지 않은 경우에는 "sip:unknown"으로 설정하여 SIP 흐름 관리에 반영한다.
// CANCEL 요청 메시지의 Via 헤더는 원본 요청 메시지의 top Via 헤더를 사용하여 SIP 흐름 관리에 반영한다. 
// CANCEL 요청 메시지의 From 헤더는 원본 요청 메시지의 From 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 CANCEL 요청 메시지에서 From 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// CANCEL 요청 메시지의 To 헤더는 원본 요청 메시지의 To 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 CANCEL 요청 메시지에서 To 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// CANCEL 요청 메시지의 Call-ID 헤더는 원본 요청 메시지의 Call-ID 헤더를 사용하되, 값이 비어있거나 최대 허용 크기를 초과하는 경우에는 CANCEL 요청 메시지에서 Call-ID 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// CANCEL 요청 메시지의 CSeq 헤더는 원본 요청 메시지의 CSeq 헤더에서 숫자 부분만 추출하여 정수로 변환한 값을 사용하되, CSeq 헤더가 비어있거나 최대 허용 크기를 초과하는 경우에는 CANCEL 요청 메시지에서 CSeq 헤더를 생략하여 SIP 흐름 관리에 반영한다. 
// SIP INVITE 요청에 대한 CANCEL 요청 메시지를 생성한 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 CANCEL 메시지를 전송할 수 있도록 구현되어 있다.
std::string SipCore::buildCancelForPending(const PendingInvite& pi) const
{
    SipMessage req;
    if (!parseSipMessage(pi.origRequest, req))
    {
         return std::string();
    }

    std::string requestUri = req.requestUri;
    if (!isValidRequestUri(requestUri))
    {
        requestUri = "sip:unknown";
    }

    std::string allVias = sanitizeHeaderValue(getHeader(req, "via"));
    std::string from    = sanitizeHeaderValue(getHeader(req, "from"));
    std::string to      = sanitizeHeaderValue(getHeader(req, "to"));
    std::string callId  = sanitizeHeaderValue(getHeader(req, "call-id"));
    std::string cseq    = sanitizeHeaderValue(getHeader(req, "cseq"));

    // RFC 3261 §9.1: CANCEL은 top Via 하나만 포함해야 함
    // 파서가 여러 Via를 콤마로 결합하므로, 첫 번째(상단) Via만 추출
    std::string via;
    {
        auto commaPos = allVias.find(',');
        via = (commaPos != std::string::npos) ? allVias.substr(0, commaPos) : allVias;
        while (!via.empty() && via.back() == ' ') via.pop_back();
    }

    int cseqNum = parseCSeqNum(cseq);

    // Route 헤더 추출 — RFC 3261 §9.1: CANCEL은 원본 요청의 Route를 포함해야 함
    std::string route = sanitizeHeaderValue(getHeader(req, "route"));

    // Max-Forwards 추출 — RFC 3261 §8.1.1: 모든 SIP 요청에 필수
    std::string maxFwd = sanitizeHeaderValue(getHeader(req, "max-forwards"));
    if (maxFwd.empty()) maxFwd = "70";

    std::ostringstream oss;
    oss << "CANCEL " << requestUri << " SIP/2.0\r\n";
    if (!via.empty())    oss << "Via: " << via << "\r\n";
    oss << "Max-Forwards: " << maxFwd << "\r\n";
    if (!route.empty())  oss << "Route: " << route << "\r\n";
    if (!from.empty())   oss << "From: " << from << "\r\n";
    if (!to.empty())     oss << "To: " << to << "\r\n";
    if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
    oss << "CSeq: " << cseqNum << " CANCEL\r\n";
    oss << "Content-Length: 0\r\n\r\n";
    return oss.str();
}

// Helper function to build simple SIP response
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성하는 헬퍼 함수인 buildSimpleResponse는 SIP 요청에 대한 적절한 SIP 응답 메시지를 생성하여 SIP 흐름 관리에 활용한다.
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성할 때, 필요한 헤더를 요청 메시지에서 추출하여 응답 메시지에 포함한다.
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성한 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송할 수 있도록 구현되어 있다.
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성할 때, To 헤더에 tag 파라미터가 없는 경우에는 reason 매개변수로 전달된 값을 tag 파라미터로 추가하여 SIP 흐름 관리에 반영한다.
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성할 때, Server 헤더를 포함하여 SIP 흐름 관리에 반영한다.
// SIP 요청에 대한 간단한 SIP 응답 메시지를 생성할 때, Content-Length 헤더를 0으로 설정하여 SIP 흐름 관리에 반영한다.
std::string SipCore::buildSimpleResponse(const SipMessage& req,
                                         int code,
                                         const std::string& reason)
{
    std::ostringstream oss;
    oss << "SIP/2.0 " << code << " " << reason << "\r\n";

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

// Helper function to build 200 OK response for REGISTER requests
// SIP REGISTER 요청에 대한 200 OK 응답 메시지를 생성하는 헬퍼 함수인 buildRegisterOk는 SIP REGISTER 요청에 대한 적절한 SIP 응답 메시지를 생성하여 SIP 흐름 관리에 활용한다.
// SIP REGISTER 요청에 대한 200 OK 응답 메시지를 생성할 때, 필요한 헤더를 요청 메시지에서 추출하여 응답 메시지에 포함한다.
// SIP REGISTER 요청에 대한 200 OK 응답 메시지를 생성할 때, To 헤더에 tag 파라미터가 없는 경우에는 "regok" + generateTag()로 생성된 값을 tag 파라미터로 추가하여 SIP 흐름 관리에 반영한다.
// SIP REGISTER 요청에 대한 200 OK 응답 메시지를 생성할 때, Contact 헤더을 요청 메시지에서 추출하여 응답 메시지에 포함한다. 
// SIP REGISTER 요청에 대한 200 OK 응답 메시지를 생성한 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송할 수 있도록 구현되어 있다.
std::string SipCore::buildRegisterOk(const SipMessage& req)
{
    std::ostringstream oss;
    oss << "SIP/2.0 200 OK\r\n";

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

std::string SipCore::buildRegisterAuthChallenge(const SipMessage& req,
                                                const std::string& nonce,
                                                bool stale)
{
    std::ostringstream oss;
    oss << "SIP/2.0 401 Unauthorized\r\n";

    std::string via    = sanitizeHeaderValue(getHeader(req, "via"));
    std::string from   = sanitizeHeaderValue(getHeader(req, "from"));
    std::string to     = sanitizeHeaderValue(getHeader(req, "to"));
    std::string callId = sanitizeHeaderValue(getHeader(req, "call-id"));
    std::string cseq   = sanitizeHeaderValue(getHeader(req, "cseq"));

    if (!via.empty())    oss << "Via: " << via << "\r\n";
    if (!from.empty())   oss << "From: " << from << "\r\n";
    if (!to.empty())     oss << "To: " << ensureToTag(to) << "\r\n";
    if (!callId.empty()) oss << "Call-ID: " << callId << "\r\n";
    if (!cseq.empty())   oss << "CSeq: " << cseq << "\r\n";

    oss << "WWW-Authenticate: Digest realm=\"" << kRegisterAuthRealm
        << "\", nonce=\"" << nonce
        << "\", algorithm=MD5, qop=\"auth\"";
    if (stale)
    {
        oss << ", stale=true";
    }
    oss << "\r\n";
    oss << "Server: SIPLite/0.1\r\n";
    oss << "Content-Length: 0\r\n";
    oss << "\r\n";
    return oss.str();
}

SipCore::DialogPeerSide SipCore::classifyDialogPeerSide(const ActiveCall& call,
                                                        const SipMessage& msg,
                                                        const UdpPacket& pkt) const
{
    const std::string fromHdr = sanitizeHeaderValue(getHeader(msg, "from"));
    const std::string toHdr = sanitizeHeaderValue(getHeader(msg, "to"));
    const std::string fromTag = extractTagFromHeader(fromHdr);
    const std::string toTag = extractTagFromHeader(toHdr);
    const std::string fromUri = extractUriFromHeader(fromHdr);
    const std::string toUri = extractUriFromHeader(toHdr);

    if (!fromTag.empty() && !toTag.empty())
    {
        if (fromTag == call.fromTag && (call.toTag.empty() || toTag == call.toTag))
        {
            return DialogPeerSide::Caller;
        }
        if (!call.toTag.empty() && fromTag == call.toTag && toTag == call.fromTag)
        {
            return DialogPeerSide::Callee;
        }
    }

    if (!fromUri.empty())
    {
        if (fromUri == call.fromUri)
        {
            return DialogPeerSide::Caller;
        }
        if (fromUri == call.toUri)
        {
            return DialogPeerSide::Callee;
        }
    }

    if (!toUri.empty())
    {
        if (toUri == call.toUri)
        {
            return DialogPeerSide::Caller;
        }
        if (toUri == call.fromUri)
        {
            return DialogPeerSide::Callee;
        }
    }

    if (pkt.remoteIp == call.callerIp && pkt.remotePort == call.callerPort)
    {
        return DialogPeerSide::Caller;
    }
    if (pkt.remoteIp == call.calleeIp && pkt.remotePort == call.calleePort)
    {
        return DialogPeerSide::Callee;
    }

    return DialogPeerSide::Unknown;
}

SipCore::DialogPeerSide SipCore::classifyDialogPeerSide(const Dialog& dlg,
                                                        const ActiveCall* call,
                                                        const SipMessage& msg,
                                                        const UdpPacket& pkt) const
{
    const std::string fromHdr = sanitizeHeaderValue(getHeader(msg, "from"));
    const std::string toHdr = sanitizeHeaderValue(getHeader(msg, "to"));
    const std::string fromTag = extractTagFromHeader(fromHdr);
    const std::string toTag = extractTagFromHeader(toHdr);

    if (!fromTag.empty() && !toTag.empty())
    {
        if (fromTag == dlg.callerTag && (dlg.calleeTag.empty() || toTag == dlg.calleeTag))
        {
            return DialogPeerSide::Caller;
        }
        if (!dlg.calleeTag.empty() && fromTag == dlg.calleeTag && toTag == dlg.callerTag)
        {
            return DialogPeerSide::Callee;
        }
    }

    if (call != nullptr)
    {
        return classifyDialogPeerSide(*call, msg, pkt);
    }

    if (pkt.remoteIp == dlg.callerIp && pkt.remotePort == dlg.callerPort)
    {
        return DialogPeerSide::Caller;
    }
    if (pkt.remoteIp == dlg.calleeIp && pkt.remotePort == dlg.calleePort)
    {
        return DialogPeerSide::Callee;
    }

    return DialogPeerSide::Unknown;
}
