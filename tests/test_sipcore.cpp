#include "SipCore.h"
#include "SipParser.h"
#include "SipUtils.h"
#include <cassert>
#include <iostream>
#include <vector>

struct SentMsg { std::string ip; uint16_t port; std::string data; TransportType transport; };

namespace
{
std::string extractChallengeValue(const std::string& response, const std::string& key)
{
    std::string pattern = key + "=\"";
    std::size_t start = response.find(pattern);
    assert(start != std::string::npos);
    start += pattern.size();
    std::size_t end = response.find('"', start);
    assert(end != std::string::npos);
    return response.substr(start, end - start);
}
}

int main()
{
    SipCore core;
    std::vector<SentMsg> sent;

    core.setSender([&sent](const std::string& ip, uint16_t port, const std::string& data, TransportType transport)->bool{
        sent.push_back({ip, port, data, transport});
        return true;
    });

    // 사전 등록 (XML 설정 대체) — handleRegister는 isStatic 단말만 허용
    core.registerTerminal("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                          "10.0.0.1", 5060, 3600);

    // 1) REGISTER
    std::string regRaw =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client.example.com:5060\r\n"
        "From: <sip:1001@server>;tag=123\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: reg1\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Contact: <sip:1001@10.0.0.1:5060>\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage regMsg;
    assert(parseSipMessage(regRaw, regMsg));

    UdpPacket regPkt{ "10.0.0.1", 5060, regRaw };
    std::string resp;
    bool ok = core.handlePacket(regPkt, regMsg, resp);
    assert(ok);
    assert(resp.find("200 OK") != std::string::npos);
    assert(core.registrationCount() == 1);
    {
        auto r = core.findRegistrationSafe("sip:1001@server");
        assert(r.has_value());
        assert(r->ip == "10.0.0.1");
        assert(r->port == 5060);
    }

    std::cout << "REGISTER flow test passed\n";

    // 1-2) REGISTER with Digest auth challenge/response
    SipCore authCore;
    authCore.registerTerminal("sip:2001@server", "<sip:2001@10.0.0.9:5060>",
                              "10.0.0.9", 5060, 3600, "s3cret");

    std::string authReq1 =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP auth.example.com:5062\r\n"
        "From: <sip:2001@server>;tag=auth1\r\n"
        "To: <sip:2001@server>\r\n"
        "Call-ID: reg-auth-1\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Contact: <sip:2001@10.0.0.9:5060>\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage authMsg1;
    assert(parseSipMessage(authReq1, authMsg1));
    UdpPacket authPkt1{"10.0.0.9", 5060, authReq1};

    ok = authCore.handlePacket(authPkt1, authMsg1, resp);
    assert(ok);
    assert(resp.find("401 Unauthorized") != std::string::npos);
    assert(resp.find("WWW-Authenticate: Digest") != std::string::npos);

    const std::string nonce = extractChallengeValue(resp, "nonce");
    const std::string realm = extractChallengeValue(resp, "realm");
    const std::string cnonce = "abcdef1234567890";
    const std::string nc = "00000001";
    const std::string uri = "sip:server";
    const std::string response = md5Hex(
        md5Hex("2001:" + realm + ":s3cret") + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" +
        md5Hex("REGISTER:" + uri));

    std::string authReq2 =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP auth.example.com:5062\r\n"
        "From: <sip:2001@server>;tag=auth1\r\n"
        "To: <sip:2001@server>\r\n"
        "Call-ID: reg-auth-1\r\n"
        "CSeq: 2 REGISTER\r\n"
        "Contact: <sip:2001@10.0.0.9:5060>\r\n"
        "Authorization: Digest username=\"2001\", realm=\"" + realm +
        "\", nonce=\"" + nonce +
        "\", uri=\"" + uri +
        "\", response=\"" + response +
        "\", algorithm=MD5, qop=auth, nc=" + nc +
        ", cnonce=\"" + cnonce + "\"\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage authMsg2;
    assert(parseSipMessage(authReq2, authMsg2));
    UdpPacket authPkt2{"10.0.0.9", 5060, authReq2};

    ok = authCore.handlePacket(authPkt2, authMsg2, resp);
    assert(ok);
    assert(resp.find("200 OK") != std::string::npos);
    auto authReg = authCore.findRegistrationSafe("sip:2001@server");
    assert(authReg.has_value());
    assert(authReg->loggedIn);

    std::cout << "REGISTER digest auth test passed\n";

    // 2) INVITE from caller 10.0.0.2 to 1001@server
    sent.clear();
    std::string invRaw =
        "INVITE sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller.example.com:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: inv1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage invMsg;
    assert(parseSipMessage(invRaw, invMsg));
    UdpPacket invPkt{ "10.0.0.2", 5060, invRaw };

    ok = core.handlePacket(invPkt, invMsg, resp);
    assert(ok);

    // Expect at least two sends: 100 Trying to caller, and forwarded INVITE to callee
    bool foundTrying = false;
    bool foundForwardInvite = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.2" && m.port == 5060 && m.data.find("100 Trying") != std::string::npos)
            foundTrying = true;
        // Request-URI는 callee의 Contact 주소로 재작성됨 (RFC 3261 §16.6)
        if (m.ip == "10.0.0.1" && m.port == 5060 && m.data.find("INVITE sip:1001@10.0.0.1:5060") != std::string::npos)
            foundForwardInvite = true;
    }
    assert(foundTrying && foundForwardInvite);
    // 프록시는 180 Ringing을 직접 생성하지 않음 — callee의 provisional 응답이 handleResponse를 통해 전달됨
    assert(resp.empty());
    assert(core.activeCallCount() == 1);

    std::cout << "INVITE flow test passed\n";

    // 3) CANCEL from caller
    sent.clear();
    std::string cancelRaw =
        "CANCEL sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller.example.com:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: inv1\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage cancelMsg;
    assert(parseSipMessage(cancelRaw, cancelMsg));

    UdpPacket cancelPkt{ "10.0.0.2", 5060, cancelRaw };
    ok = core.handlePacket(cancelPkt, cancelMsg, resp);
    assert(ok);

    // Expect sent messages: 200 OK for CANCEL to caller (via outResponse) and CANCEL forwarded to callee
    bool foundCancelToCallee = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.1" && m.data.find("CANCEL ") == 0)
            foundCancelToCallee = true;
    }

    // outResponse should be 200 OK for CANCEL
    assert(resp.find("200 OK") != std::string::npos);
    assert(foundCancelToCallee);

    // 487 Request Terminated는 callee의 487 응답이 handleResponse를 통해 caller에게 전달됨
    // 여기서는 callee의 487 응답을 시뮬레이션하여 검증
    sent.clear();
    std::string resp487Raw =
        "SIP/2.0 487 Request Terminated\r\n"
        "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-proxy-test;rport\r\n"
        "Via: SIP/2.0/UDP caller.example.com:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>;tag=callee-tag\r\n"
        "Call-ID: inv1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage resp487Msg;
    assert(parseSipMessage(resp487Raw, resp487Msg));
    UdpPacket resp487Pkt{ "10.0.0.1", 5060, resp487Raw };
    bool handled = core.handleResponse(resp487Pkt, resp487Msg);
    assert(handled);

    bool found487ToCaller = false;
    bool foundAckToCallee = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.2" && m.data.find("487 Request Terminated") != std::string::npos)
            found487ToCaller = true;
        if (m.ip == "10.0.0.1" && m.data.find("ACK ") == 0)
            foundAckToCallee = true;
    }
    assert(found487ToCaller);
    assert(foundAckToCallee);
    assert(core.activeCallCount() == 0);

    std::cout << "CANCEL flow test passed\n";

    std::cout << "All SipCore tests passed\n";
    return 0;
}
