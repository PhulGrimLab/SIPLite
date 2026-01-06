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
    std::string callId = getHeader(msg, "call-id");
    std::string cseq  = getHeader(msg, "cseq");
    if (callId.empty() || cseq.empty())
        return false;

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

    if (sender_)
    {
        sender_(it->second.callerIp, it->second.callerPort, pkt.data);
    }

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
            std::string cseq = getHeader(msg, "cseq");
            std::string method;
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
                std::lock_guard<std::mutex> lock1(callMutex_);
                std::lock_guard<std::mutex> lock2(pendingInvMutex_);

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

            {
                std::lock_guard<std::mutex> lockd(dlgMutex_);
                auto dit = dialogs_.find(callId);
                if (dit != dialogs_.end() && dit->second.confirmed)
                {
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
    std::string toUser = extractUserFromUri(toUri);
    (void)toUser;

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

    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto it = pendingInvites_.find(key);
        if (it != pendingInvites_.end())
        {
            if (!it->second.lastResponse.empty() && sender_)
            {
                sender_(pkt.remoteIp, pkt.remotePort, it->second.lastResponse);
            }
            else if (sender_)
            {
                sender_(pkt.remoteIp, pkt.remotePort, buildSimpleResponse(msg, 100, "Trying"));
            }
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

    outResponse = buildInviteResponse(msg, 180, "Ringing", activeCalls_[callId].toTag, "");

    return true;
}

bool SipCore::handleAck(const UdpPacket& pkt,
                        const SipMessage& msg,
                        std::string& outResponse)
{
    std::string callId = getHeader(msg, "call-id");
    std::string cseqHdr = getHeader(msg, "cseq");

    if (callId.empty())
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(callMutex_);
        auto it = activeCalls_.find(callId);
        if (it != activeCalls_.end())
        {
            it->second.confirmed = true;
            if (sender_)
            {
                sender_(it->second.calleeIp, it->second.calleePort, pkt.data);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(dlgMutex_);
        auto dit = dialogs_.find(callId);
        if (dit != dialogs_.end())
        {
            dit->second.confirmed = true;
        }
    }

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

    outResponse.clear();
    return true;
}

bool SipCore::handleBye(const UdpPacket& pkt,
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

    outResponse = buildSimpleResponse(msg, 481, "Call/Transaction Does Not Exist");
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

    int cseqNum = 0;
    size_t i = 0;
    while (i < cseqHdr.size() && std::isspace((unsigned char)cseqHdr[i])) ++i;
    while (i < cseqHdr.size() && std::isdigit((unsigned char)cseqHdr[i]))
    {
        cseqNum = cseqNum*10 + (cseqHdr[i]-'0');
        ++i;
    }

    std::string key = callId + ":" + std::to_string(cseqNum);

    {
        std::lock_guard<std::mutex> lock(pendingInvMutex_);
        auto pit = pendingInvites_.find(key);
        if (pit != pendingInvites_.end())
        {
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

            std::string cancelRaw = buildCancelForPending(pit->second);
            if (!cancelRaw.empty() && !calleeIp.empty() && sender_)
            {
                sender_(calleeIp, calleePort, cancelRaw);
            }

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

            pit->second.state = TxState::COMPLETED;
            pit->second.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(8);

            {
                std::lock_guard<std::mutex> lock2(callMutex_);
                auto it = activeCalls_.find(callId);
                if (it != activeCalls_.end() && !it->second.confirmed)
                    activeCalls_.erase(it);
            }
        }
        else
        {
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

    if (tag.size() > 128)
    {
        return "";
    }

    return tag;
}

std::string SipCore::generateTag() const
{
    static thread_local std::mt19937 gen([]() -> std::mt19937::result_type {
        std::random_device rd;
        try {
            return static_cast<std::mt19937::result_type>(rd());
        } catch (...) {
            auto seed = static_cast<std::mt19937::result_type>(
                std::chrono::steady_clock::now().time_since_epoch().count() ^
                std::hash<std::thread::id>{}(std::this_thread::get_id()));
            return seed;
        }
    }());
    static thread_local std::uniform_int_distribution<uint32_t> dis(
        0, std::numeric_limits<uint32_t>::max());

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
