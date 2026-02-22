#include "SipCore.h"
#include "SipParser.h"

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

    // SIP 메서드 대소문자 구분 없이 처리 - SIP 표준에서는 메서드 이름이 대소문자 구분 없이 처리되어야 합니다.
    // 예: "invite", "INVITE", "InViTe" 모두 같은 메서드로 처리되어야 합니다.
    // 따라서 메서드 이름을 대문자로 변환하여 비교합니다.
    // C++17에서는 std::transform과 ::toupper를 사용하여 문자열을 대문자로 변환할 수 있습니다.
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

bool SipCore::handleResponse(const UdpPacket& pkt, const SipMessage& msg)
{
    // SIP 응답은 SIP 흐름(예: INVITE → 100 Trying → 180 Ringing → 200 OK 등)의 일부로 처리됩니다.
    // 따라서 응답 메시지의 상태 코드와 CSeq 헤더를 기반으로 적절한 처리를 수행해야 합니다.
    // 예: INVITE에 대한 100 Trying/180 Ringing/200 OK 응답 처리, CANCEL에 대한 200 OK 응답 처리 등.

    // SIP 응답은 SIP 흐름의 일부로 처리되므로, 일반적으로 외부에서 직접 응답을 생성하여 반환하는 경우는 드뭅니다.
    // 대신, SIP 흐름 처리 중에 필요한 경우 sender_ 콜백을 통해 네트워크로 응답을 전송하는 방식으로 구현됩니다.

    std::string callId = getHeader(msg, "call-id");
    std::string cseq  = getHeader(msg, "cseq");

    if (callId.empty() || cseq.empty())
    {
        return false;
    }

    // CSeq 헤더에서 숫자 부분만 추출하여 정수로 변환
    // CSeq 헤더는 일반적으로 "CSeq: 123 INVITE"와 같은 형식으로 되어 있습니다.
    // 따라서 숫자 부분만 추출하여 정수로 변환해야 합니다.
    int cseqNum = parseCSeqNum(cseq);
    if (cseqNum < 0)
    {
        return false;
    }

    // callId + cseqNum을 키로 하여 pendingInvites_에서 해당 INVITE 트랜잭션이 존재하는지 확인
    // SIP 응답은 일반적으로 INVITE 트랜잭션과 연관되어 처리됩니다.
    // 따라서 응답 메시지의 call-id와 cseq 헤더를 기반으로 해당 트랜잭션이 pendingInvites_에 존재하는지 확인해야 합니다.
    // 예: INVITE 트랜잭션이 존재하는 경우, 100 Trying/180 Ringing/200 OK 응답에 따라 트랜잭션 상태를 업데이트하거나, 
    // CANCEL 트랜잭션이 존재하는 경우 200 OK 응답에 따라 트랜잭션을 종료하는 등의 처리가 필요할 수 있습니다.
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
        // SIP 응답은 일반적으로 INVITE 트랜잭션과 연관되어 처리됩니다.
        // 따라서 응답 메시지의 call-id와 cseq 헤더를 기반으로 해당 트랜잭션이 pendingInvites_에 존재하는지 확인해야 합니다.
        auto it = pendingInvites_.find(key);
        if (it == pendingInvites_.end())
        {
            return false;
        }

        // Collect forwarding info (send outside lock)
        fwdIp = it->second.callerIp;
        fwdPort = it->second.callerPort;
        fwdData = pkt.data;

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
                    // 2xx 응답이 INVITE에 대한 것인 경우에만 Dialog를 생성합니다.
                    // Dialog 생성 시, callId, callerTag(From 헤더의 tag), 
                    // calleeTag(To 헤더의 tag), callerIp/Port, calleeIp/Port, cseqNum, 생성 시간 등을 설정합니다.  
                    // 또한, 2xx 응답에 SDP 바디가 포함된 경우, 
                    // ActiveCall의 lastSdp 및 lastSdpContentType 필드에 해당 정보를 저장하여 SIP 흐름 관리에 활용할 수 있도록 합니다.
                    // Dialog 생성은 SIP 흐름 관리에 중요한 역할을 합니다. 
                    // Dialog를 통해 SIP 메시지의 흐름을 추적하고, ACK 전송 여부를 결정하는 등의 처리를 수행할 수 있습니다.
                    auto acIt = activeCalls_.find(callId);
                    if (acIt != activeCalls_.end())
                    {
                        Dialog dlg;
                        dlg.callId = callId;
                        dlg.callerTag = acIt->second.fromTag;
                        std::string toHdr = getHeader(msg, "to");
                        dlg.calleeTag = extractTagFromHeader(toHdr);
                        dlg.callerIp = it->second.callerIp;
                        dlg.callerPort = it->second.callerPort;
                        dlg.calleeIp = pkt.remoteIp;
                        dlg.calleePort = pkt.remotePort;
                        dlg.cseq = cseqNum;
                        dlg.created = std::chrono::steady_clock::now();
                        dlg.confirmed = false;

                        std::string body = msg.body;
                        std::string ctype = getHeader(msg, "content-type");
                        if (!body.empty())
                        {
                            acIt->second.lastSdp = body;
                            acIt->second.lastSdpContentType = ctype.empty() ? "application/sdp" : ctype;
                        }
                        
                        // Dialog를 생성하여 dialogs_ 맵에 저장합니다.
                        dialogs_[callId] = std::move(dlg);
                    }
                }

                // ACK 전송 필요 여부 확인
                // 2xx 응답에 대한 ACK는 SIP 흐름 관리에 중요한 역할을 합니다.
                // ACK 전송 여부는 Dialog의 confirmed 필드로 관리할 수 있습니다.
                // ACK 전송이 필요한 경우, buildAckForPending 함수를 사용하여 ACK 메시지를 생성하고,
                // sender_ 콜백을 통해 네트워크로 전송할 수 있도록 합니다
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
                            // ACK 메시지를 생성하여 ackData에 저장합니다.
                            ackData = std::move(ack);
                        }
                    }
                }
            }
            else
            {
                // 3xx-6xx 에러 응답: 프록시가 ACK 생성 필요 (RFC 3261 §16.7)
                // 3xx-6xx 응답에 대한 ACK 생성 여부는 SIP 흐름 관리에 중요한 역할을 합니다.
                // 프록시가 ACK를 생성해야 하는 경우, buildAckForPending 함수를 사용하여 ACK 메시지를 생성하고, 
                // sender_ 콜백을 통해 네트워크로 전송할 수 있도록 합니다.
                std::string ack = buildAckForPending(it->second, pkt.data);
                if (!ack.empty())
                {
                    ackIp = pkt.remoteIp;
                    ackPort = pkt.remotePort;
                    // ACK 메시지를 생성하여 ackData에 저장합니다.
                    ackData = std::move(ack);
                }

                // 에러 응답 시 ActiveCall 및 Dialog 정리
                activeCalls_.erase(callId);
                dialogs_.erase(callId);
            }
        }
    } // all locks released

    // Send outside locks (#3 fix)
    // SIP 응답 처리 후, 필요한 경우 sender_ 콜백을 통해 네트워크로 메시지를 전송합니다.
    // SIP 응답 처리 중에 수집된 정보를 기반으로, 
    // fwdData(원본 응답 메시지)와 ackData(생성된 ACK 메시지)를 sender_ 콜백을 통해 전송합니다.
    if (sender_)
    {
        // fwdData는 원본 응답 메시지로, ACK는 SIP 흐름 관리에 필요한 경우에만 생성됩니다.
        // 따라서, fwdData와 ackData가 모두 존재하는 경우에는 원본 응답 메시지와 ACK 메시지를 모두 전송할 수 있도록 합니다.
        if (!fwdData.empty())
        {
            sender_(fwdIp, fwdPort, fwdData);
        }

        // ACK는 SIP 흐름 관리에 필요한 경우에만 생성되므로, ackData가 존재하는 경우에만 전송하도록 합니다.
        if (!ackData.empty())
        {
            sender_(ackIp, ackPort, ackData);
        }
    }

    return true;
}

bool SipCore::handleRegister(const UdpPacket& pkt,
                             const SipMessage& msg,
                             std::string& outResponse)
{
    std::string toHdr      = getHeader(msg, "to");
    std::string contactHdr = getHeader(msg, "contact");

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

    int expiresSec = SipConstants::DEFAULT_EXPIRES_SEC;
    std::string expHdr = getHeader(msg, "expires");
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
    if (expiresSec == 0)
    {
        std::lock_guard<std::mutex> lock(regMutex_);
        regs_.erase(aor);
        outResponse = buildRegisterOk(msg);
        return true;
    }

    Registration reg;
    reg.aor      = aor;
    reg.contact  = contactHdr;
    reg.ip       = pkt.remoteIp;
    reg.port     = pkt.remotePort;
    reg.expiresAt = std::chrono::steady_clock::now() +
                    std::chrono::seconds(expiresSec);

    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = regs_.find(aor);
        if (it == regs_.end() && regs_.size() >= SipConstants::MAX_REGISTRATIONS)
        {
            outResponse = buildSimpleResponse(msg, 503, "Service Unavailable");
            return true;
        }
        regs_[aor] = reg;
    }

    outResponse = buildRegisterOk(msg);
    return true;
}

bool SipCore::handleInvite(const UdpPacket& pkt,
                           const SipMessage& msg,
                           std::string& outResponse)
{
    std::string toHdr     = getHeader(msg, "to");
    std::string fromHdr   = getHeader(msg, "from");
    std::string callId    = getHeader(msg, "call-id");
    std::string cseqHdr   = getHeader(msg, "cseq");

    if (toHdr.empty() || fromHdr.empty() || callId.empty() || cseqHdr.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    std::string toUri = extractUriFromHeader(toHdr);

    std::string targetAor = toUri;
    Registration regCopy;
    bool found = false;

    {
        std::lock_guard<std::mutex> lock(regMutex_);
        auto it = regs_.find(targetAor);
        if (it != regs_.end())
        {
            if (it->second.expiresAt > std::chrono::steady_clock::now())
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
    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    if (sender_)
    {
        sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"));
    }
    else
    {
        outResponse = buildSimpleResponse(msg, 100, "Trying");
    }

    std::string fromTag = extractTagFromHeader(fromHdr);
    std::string toTag = generateTag();

    {
        std::lock_guard<std::mutex> lock(callMutex_);
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

    std::string key = callId + ":" + std::to_string(cseqNum);

    // Check for retransmission (duplicate INVITE)
    std::string retransmitData;
    bool isRetransmit = false;
    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto it = pendingInvites_.find(key);
        if (it != pendingInvites_.end())
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

    if (isRetransmit)
    {
        if (sender_ && !retransmitData.empty())
        {
            sender_(pkt.remoteIp, pkt.remotePort, retransmitData);
        }
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        PendingInvite pi;
        pi.callerIp = pkt.remoteIp;
        pi.callerPort = pkt.remotePort;
        pi.calleeIp = regCopy.ip;
        pi.calleePort = regCopy.port;
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

    // toTag는 로컬 변수 사용 — activeCalls_ 접근 시 callMutex_ 필요 (data race 방지)
    outResponse = buildInviteResponse(msg, 180, "Ringing", toTag, "");

    return true;
}

bool SipCore::handleAck(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse)
{
    std::string callId = getHeader(msg, "call-id");
    std::string cseqHdr = getHeader(msg, "cseq");

    if (callId.empty() || cseqHdr.empty())
    {
        return false;
    }

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
        return false;

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
            it->second.confirmed = true;
            ackFwdIp = it->second.calleeIp;
            ackFwdPort = it->second.calleePort;
        }

        auto dit = dialogs_.find(callId);
        if (dit != dialogs_.end())
        {
            dit->second.confirmed = true;
        }

        std::string key = callId + ":" + std::to_string(cseqNum);
        pendingInvites_.erase(key);
    }

    // Send ACK to callee outside all locks
    if (sender_ && !ackFwdIp.empty())
    {
        sender_(ackFwdIp, ackFwdPort, pkt.data);
    }

    outResponse.clear();
    return true;
}

bool SipCore::handleBye(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse)
{
    std::string callId = getHeader(msg, "call-id");

    if (callId.empty())
    {
        outResponse = buildSimpleResponse(msg, 400, "Bad Request");
        return true;
    }

    bool found = false;
    std::string fwdIp;
    uint16_t fwdPort = 0;
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
                fwdIp = dit->second.calleeIp;
                fwdPort = dit->second.calleePort;
            }
            else
            {
                fwdIp = dit->second.callerIp;
                fwdPort = dit->second.callerPort;
            }
            dialogs_.erase(dit);
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
            activeCalls_.erase(it);
        }

        // PendingInvite 정리
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

    if (found)
    {
        outResponse = buildSimpleResponse(msg, 200, "OK");

        // BYE를 상대방에게 전달 (B2BUA/프록시 동작)
        if (sender_ && !fwdIp.empty())
        {
            sender_(fwdIp, fwdPort, pkt.data);
        }
    }
    else
    {
        outResponse = buildSimpleResponse(msg, 481, "Call/Transaction Does Not Exist");
    }
    return true;
}

bool SipCore::handleCancel(const UdpPacket& pkt,
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

    outResponse = buildSimpleResponse(msg, 200, "OK");

    int cseqNum = parseCSeqNum(cseqHdr);
    if (cseqNum < 0)
        return true; // 200 OK already set, but can't process further

    std::string key = callId + ":" + std::to_string(cseqNum);

    // Collect data under locks (correct order: callMutex_ -> pendingInvMutex_ -> dlgMutex_)
    std::string calleeIp;
    uint16_t calleePort = 0;
    std::string cancelRaw;
    std::string resp487;
    std::string callerIp;
    uint16_t callerPort = 0;
    bool foundPending = false;

    {
        std::lock_guard<std::mutex> lockCall(callMutex_);
        std::lock_guard<std::mutex> lockPend(pendingInvMutex_);
        std::lock_guard<std::mutex> lockDlg(dlgMutex_);

        auto pit = pendingInvites_.find(key);
        if (pit != pendingInvites_.end())
        {
            foundPending = true;

            // PendingInvite에서 callee 정보 가져오기 (#1 fix)
            calleeIp = pit->second.calleeIp;
            calleePort = pit->second.calleePort;
            callerIp = pit->second.callerIp;
            callerPort = pit->second.callerPort;

            // callee에게 전달할 CANCEL 생성
            cancelRaw = buildCancelForPending(pit->second);

            // caller에게 보낼 487 Request Terminated 생성 (#2 fix)
            SipMessage pendingReq;
            if (parseSipMessage(pit->second.origRequest, pendingReq))
            {
                resp487 = buildSimpleResponse(pendingReq, 487, "Request Terminated");
            }

            // PendingInvite 정리 — 제거
            pendingInvites_.erase(pit);

            // ActiveCall 및 Dialog 정리
            activeCalls_.erase(callId);
            dialogs_.erase(callId);
        }
        else
        {
            // No pending invite found — just clean up unconfirmed call
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
            sender_(calleeIp, calleePort, cancelRaw);
        }
        if (!resp487.empty() && !callerIp.empty())
        {
            sender_(callerIp, callerPort, resp487);
        }
    }

    return true;
}

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

std::string SipCore::generateTag() const
{
    static thread_local std::mt19937_64 gen([]() -> std::mt19937_64::result_type {
        std::random_device rd;
        try {
            // Combine two 32-bit values for a 64-bit seed
            uint64_t hi = static_cast<uint64_t>(rd()) << 32;
            uint64_t lo = static_cast<uint64_t>(rd());
            return static_cast<std::mt19937_64::result_type>(hi | lo);
        } catch (...) {
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

std::string SipCore::buildAckForPending(const PendingInvite& pi, const std::string& respRaw) const
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

    int cseqNum = parseCSeqNum(cseq);

    std::ostringstream oss;
    oss << "ACK " << requestUri << " SIP/2.0\r\n";

    // RFC 3261 §17.1.1.3: ACK의 Via는 원본 요청의 top Via 사용
    std::string via = sanitizeHeaderValue(getHeader(req, "via"));
    if (!via.empty()) oss << "Via: " << via << "\r\n";

    if (!fromHdr.empty()) oss << "From: " << fromHdr << "\r\n";
    if (!toHdr.empty())   oss << "To: " << toHdr << "\r\n";
    if (!callId.empty())  oss << "Call-ID: " << callId << "\r\n";

    oss << "CSeq: " << cseqNum << " ACK\r\n";
    oss << "Content-Length: 0\r\n\r\n";

    return oss.str();
}

std::string SipCore::buildCancelForPending(const PendingInvite& pi) const
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

    int cseqNum = parseCSeqNum(cseq);

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
