#include "SipParser.h"
#include "SipCore.h"
#include <iostream>
#include <cassert>

int main()
{
    {
        std::string raw = "INVITE sip:1000@server SIP/2.0\r\n"
                          "Via: SIP/2.0/UDP client.example.com:5060\r\n"
                          "From: <sip:1001@client>;tag=123\r\n"
                          "To: <sip:1000@server>\r\n"
                          "Call-ID: abc123\r\n"
                          "CSeq: 1 INVITE\r\n"
                          "Content-Length: 0\r\n\r\n";
        SipMessage msg;
        bool ok = parseSipMessage(raw, msg);
        assert(ok);
        assert(msg.type == SipType::Request);
        assert(msg.method == "INVITE");
        assert(msg.requestUri == "sip:1000@server");
        std::cout << "Parser basic test passed\n";
    }

    {
        std::string raw = "SIP/2.0 200 OK\r\n"
                          "Via: SIP/2.0/UDP client.example.com:5060\r\n"
                          "From: <sip:1001@client>;tag=123\r\n"
                          "To: <sip:1000@server>;tag=xyz\r\n"
                          "Call-ID: abc123\r\n"
                          "CSeq: 1 INVITE\r\n"
                          "Content-Length: 0\r\n\r\n";
        SipMessage msg;
        bool ok = parseSipMessage(raw, msg);
        assert(ok);
        assert(msg.type == SipType::Response);
        assert(msg.statusCode == 200);
        std::cout << "Parser response test passed\n";
    }

    std::cout << "All parser tests passed\n";
    return 0;
}
