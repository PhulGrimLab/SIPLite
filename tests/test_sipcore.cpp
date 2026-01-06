#include "SipCore.h"
#include "SipParser.h"
#include <cassert>
#include <iostream>
#include <vector>

struct SentMsg { std::string ip; uint16_t port; std::string data; };

int main()
{
    SipCore core;
    std::vector<SentMsg> sent;

    core.setSender([&sent](const std::string& ip, uint16_t port, const std::string& data)->bool{
        sent.push_back({ip, port, data});
        return true;
    });

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
        if (m.ip == "10.0.0.1" && m.port == 5060 && m.data.find("INVITE sip:1001@server") != std::string::npos)
            foundForwardInvite = true;
    }
    assert(foundTrying && foundForwardInvite);
    assert(resp.find("180 Ringing") != std::string::npos);
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

    // Expect sent messages: 200 OK for CANCEL to caller (via outResponse) and CANCEL forwarded to callee; and 487 to caller
    bool foundCancelToCallee = false;
    bool found487ToCaller = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.1" && m.data.find("CANCEL ") == 0)
            foundCancelToCallee = true;
        if (m.ip == "10.0.0.2" && m.data.find("487 Request Terminated") != std::string::npos)
            found487ToCaller = true;
    }

    // outResponse should be 200 OK for CANCEL
    assert(resp.find("200 OK") != std::string::npos);
    assert(foundCancelToCallee);
    assert(found487ToCaller);
    assert(core.activeCallCount() == 0);

    std::cout << "CANCEL flow test passed\n";

    std::cout << "All SipCore tests passed\n";
    return 0;
}
