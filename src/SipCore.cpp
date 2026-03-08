#include "SipCore.h"
#include "SipParser.h"
#include "Logger.h"

#include <sstream>
#include <algorithm>
#include <charconv>

bool SipCore::handlePacket(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    outResponse.clear();

    if (msg.type != SipType::Request)
    {
        return false;
    }

    // SIP 메서드 대소문자 구분 없이 처리 - SIP 표준에서는 메서드 이름이 대소문자 구분 없이 처리되어야 한다.
    // 예: "invite", "INVITE", "InViTe" 모두 같은 메서드로 처리되어야 한다.
    // 따라서 메서드 이름을 대문자로 변환하여 비교한다.
    // C++17에서는 std::transform과 ::toupper를 사용하여 문자열을 대문자로 변환할 수 있다.
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
    std::string fwdData;
    std::string ackData;
    std::string ackIp;
    uint16_t ackPort = 0;

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
                        dlg.calleeIp = pkt.remoteIp;
                        dlg.calleePort = pkt.remotePort;
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
            sender_(fwdIp, fwdPort, fwdData);
        }

        // ACK는 SIP 흐름 관리에 필요한 경우에만 생성되므로, ackData가 존재하는 경우에만 전송한다.
        if (!ackData.empty())
        {
            sender_(ackIp, ackPort, ackData);
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
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = findByUser_(aor);
        if (it == regs_.end() || !it->second.isStatic)
        {
            outResponse = buildSimpleResponse(msg, 403, "Forbidden");
            return true;
        }
        matchedAor = it->first;
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
    reg.expiresAt = std::chrono::steady_clock::now() +
                    std::chrono::seconds(expiresSec);
    reg.loggedIn = true;
    reg.isStatic = true;  // 여기에 도달하는 단말은 항상 isStatic

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
        }
    }

    if (!found)
    {
        outResponse = buildSimpleResponse(msg, 404, "Not Found");
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
            sender_(pkt.remoteIp, pkt.remotePort, retransmitData);
        }
        return true;
    }

    // ===== 재전송이 아닌 새로운 INVITE만 여기 도달 =====

    // 100 Trying은 새로운 INVITE에 대해서만 전송
    if (sender_)
    {
        sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"));
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
    std::string fwdInvite = addProxyVia(pkt.data);
    fwdInvite = addRecordRoute(fwdInvite);  // Record-Route 추가 — in-dialog 요청이 프록시를 경유하도록 보장
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
        call.calleeIp = regCopy.ip;
        call.calleePort = regCopy.port;
        call.startTime = std::chrono::steady_clock::now();
        call.confirmed = false;
        activeCalls_[callId] = call;

        PendingInvite pi;
        pi.callerIp = pkt.remoteIp;
        pi.callerPort = pkt.remotePort;
        pi.calleeIp = regCopy.ip;
        // caller의 Contact URI 저장 (BYE 전달 시 Request-URI 재작성용)
        {
            std::string callerContactHdr = sanitizeHeaderValue(getHeader(msg, "contact"));
            pi.callerContact = extractUriFromHeader(callerContactHdr);
        }
        pi.calleePort = regCopy.port;
        // 프록시 Via가 추가된 버전을 저장하여, CANCEL/ACK 생성 시 callee가 받은 Via와 일치하도록 함
        pi.origRequest = fwdInvite;
        // caller의 원본 INVITE를 저장하여, 487 응답 생성 시 프록시 Via 없는 버전을 사용
        pi.callerRequest = pkt.data;
        pi.ts = std::chrono::steady_clock::now();
        pi.state = TxState::TRYING;
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
                sender_(pkt.remoteIp, pkt.remotePort, resp487ForCaller);
            }
        }

        outResponse.clear();
        return true;
    }

    if (sender_)
    {
        sender_(regCopy.ip, regCopy.port, fwdInvite);
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
    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            Logger::instance().info("[handleAck] ActiveCall found: callId=" + callId
                + " callerIp=" + it->second.callerIp + ":" + std::to_string(it->second.callerPort)
                + " calleeIp=" + it->second.calleeIp + ":" + std::to_string(it->second.calleePort)
                + " pktFrom=" + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));

            it->second.confirmed = true;
            ackFwdIp = it->second.calleeIp;
            ackFwdPort = it->second.calleePort;
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
        // ACK에 프록시 Via 추가 및 자신을 가리키는 Route 헤더 제거 후 전달
        std::string fwdAck = addProxyVia(pkt.data);
        fwdAck = stripOwnRoute(fwdAck);
        sender_(ackFwdIp, ackFwdPort, fwdAck);
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
    std::string fwdIp;
    uint16_t fwdPort = 0;
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
            found = true;
            // BYE 발신자를 판별하여 상대방에게 전달
            if (pkt.remoteIp == dit->second.callerIp &&
                pkt.remotePort == dit->second.callerPort)
            {
                // caller가 BYE 보냄 → callee에게 전달
                fwdIp = dit->second.calleeIp;
                fwdPort = dit->second.calleePort;
                fwdContactUri = dit->second.remoteTarget;  // callee의 Contact URI
            }
            else
            {
                // callee가 BYE 보냄 → caller에게 전달
                fwdIp = dit->second.callerIp;
                fwdPort = dit->second.callerPort;
                fwdContactUri = dit->second.callerContact; // caller의 Contact URI
            }

            dialogs_.erase(dit);    // Dialog를 삭제하여 SIP 흐름 관리에 반영한다.
        }

        // ActiveCall에서도 상대방 정보 조회 (Dialog가 없는 경우)
        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            if (!found)
            {
                found = true;
                if (pkt.remoteIp == it->second.callerIp &&
                    pkt.remotePort == it->second.callerPort)
                {
                    fwdIp = it->second.calleeIp;
                    fwdPort = it->second.calleePort;
                }
                else
                {
                    fwdIp = it->second.callerIp;
                    fwdPort = it->second.callerPort;
                }
            }

            activeCalls_.erase(it);    // ActiveCall에서 해당 통화를 삭제하여 SIP 흐름 관리에 반영한다.
        }

        // PendingInvite 정리
        for (auto pit = pendingInvites_.begin(); pit != pendingInvites_.end(); )
        {
            if (pit->first.rfind(callId + ":", 0) == 0)
            {
                // 해당 Call-ID로 시작하는 모든 PendingInvite를 pendingInvites_에서 제거하여 SIP 흐름 관리에 반영한다.
                pit = pendingInvites_.erase(pit);   
            }
            else
            {
                // Call-ID가 일치하지 않는 경우에는 다음 PendingInvite로 이동한다.
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
            // BYE에 프록시 Via 추가 및 자신을 가리키는 Route 헤더 제거 후 전달
            std::string fwdBye = addProxyVia(pkt.data);
            fwdBye = stripOwnRoute(fwdBye);

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

            sender_(fwdIp, fwdPort, fwdBye);
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

    outResponse = buildSimpleResponse(msg, 200, "OK");

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        return true; // 200 OK already set, but can't process further
    }

    std::string key = callId + ":" + std::to_string(cseqNum);

    // Collect data under locks (correct order: callMutex_ -> pendingInvMutex_ -> dlgMutex_)
    std::string calleeIp;
    uint16_t calleePort = 0;
    std::string cancelRaw;
    bool foundPending = false;

    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto pit = pendingInvites_.find(key);
        if (pit != pendingInvites_.end())
        {
            foundPending = true;

            // PendingInvite에서 callee 정보 가져오기
            calleeIp = pit->second.calleeIp;
            calleePort = pit->second.calleePort;

            // callee에게 전달할 CANCEL 생성
            cancelRaw = buildCancelForPending(pit->second);

            // pendingInvite를 삭제하지 않음 — callee의 487 응답이 handleResponse를 통해
            // 정상적으로 처리되도록 함 (caller에게 487 전달 + callee에게 ACK)
            // RFC 3261 §16.10: 프록시는 CANCEL을 전달하고, callee의 응답을 그대로 caller에게 전달해야 함
        }
        else
        {
            // PendingInvite가 아직 없음 — INVITE보다 CANCEL이 먼저 처리된 경합 상황
            // 보류 CANCEL 목록에 등록하여, INVITE가 PendingInvite를 생성할 때 즉시 취소 처리하도록 함
            pendingCancels_.insert(key);
            Logger::instance().info("[handleCancel] PendingInvite not yet created, deferring cancel: key=" + key);

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
            sender_(calleeIp, calleePort, cancelRaw);
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

    oss << "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER\r\n";
    oss << "Accept: application/sdp\r\n";
    oss << "Server: SIPLite/0.1\r\n";
    oss << "Content-Length: 0\r\n";
    oss << "\r\n";

    outResponse = oss.str();
    return true;
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

// 프록시 Via 헤더 추가 (RFC 3261 §16.6)
// INVITE를 callee에게 전달할 때, 프록시 자신의 Via를 최상단에 삽입하여
// callee의 응답이 반드시 프록시를 경유하도록 보장한다.
std::string SipCore::addProxyVia(const std::string& rawMsg) const
{
    auto pos = rawMsg.find("\r\n");
    if (pos == std::string::npos) return rawMsg;

    std::string branch = "z9hG4bK-proxy-" + generateTag();
    std::string addr = localAddr_.empty() ? "127.0.0.1" : localAddr_;
    uint16_t port = localPort_ ? localPort_ : 5060;

    std::string via = "Via: SIP/2.0/UDP " + addr + ":" + std::to_string(port)
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
std::string SipCore::addRecordRoute(const std::string& rawMsg) const
{
    auto pos = rawMsg.find("\r\n");
    if (pos == std::string::npos) return rawMsg;

    std::string addr = localAddr_.empty() ? "127.0.0.1" : localAddr_;
    uint16_t port = localPort_ ? localPort_ : 5060;

    // lr 파라미터: loose routing (RFC 3261 §16.6)
    std::string rr = "Record-Route: <sip:" + addr + ":" + std::to_string(port) + ";lr>\r\n";

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
std::string SipCore::stripOwnRoute(const std::string& rawMsg) const
{
    std::string addr = localAddr_.empty() ? "127.0.0.1" : localAddr_;
    uint16_t port = localPort_ ? localPort_ : 5060;
    std::string selfUri = addr + ":" + std::to_string(port);

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
        if (line.find(selfUri) != std::string::npos)
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
