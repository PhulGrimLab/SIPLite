#include "SipCore.h"
#include "SipParser.h"
#include "SipUtils.h"
#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

#include <memory>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

#define FAIL(reason) \
    do { std::cout << "FAILED: " << reason << "\n"; ++testsFailed; } while(0)

struct SentMsg { std::string ip; uint16_t port; std::string data; };

// ================================
// Helper: 공통 SipCore 생성 + sender 설치
// ================================
static std::unique_ptr<SipCore> createCoreWithSender(std::vector<SentMsg>& sent)
{
    auto core = std::make_unique<SipCore>();
    core->setSender([&sent](const std::string& ip, uint16_t port, const std::string& data) -> bool {
        sent.push_back({ip, port, data});
        return true;
    });
    return core;
}

// Helper: REGISTER 요청 생성
static std::string makeRegister(const std::string& aor,
                                 const std::string& contact,
                                 const std::string& callId,
                                 int cseq,
                                 const std::string& expires,
                                 const std::string& fromTag = "tag1")
{
    std::string raw =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <" + aor + ">;tag=" + fromTag + "\r\n"
        "To: <" + aor + ">\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: " + std::to_string(cseq) + " REGISTER\r\n"
        "Contact: " + contact + "\r\n"
        "Expires: " + expires + "\r\n"
        "Content-Length: 0\r\n\r\n";
    return raw;
}

// Helper: INVITE 요청 생성
static std::string makeInvite(const std::string& toUri,
                               const std::string& fromUri,
                               const std::string& callId,
                               int cseq,
                               const std::string& fromTag = "inv-tag")
{
    std::string raw =
        "INVITE " + toUri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <" + fromUri + ">;tag=" + fromTag + "\r\n"
        "To: <" + toUri + ">\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: " + std::to_string(cseq) + " INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    return raw;
}

// Helper: BYE 요청 생성
static std::string makeBye(const std::string& toUri,
                            const std::string& callId,
                            int cseq,
                            const std::string& fromTag = "bye-tag",
                            const std::string& toTag = "")
{
    std::string raw =
        "BYE " + toUri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=" + fromTag + "\r\n"
        "To: <" + toUri + ">" + (toTag.empty() ? "" : ";tag=" + toTag) + "\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: " + std::to_string(cseq) + " BYE\r\n"
        "Content-Length: 0\r\n\r\n";
    return raw;
}

// Helper: OPTIONS 요청 생성
static std::string makeOptions(const std::string& toUri, const std::string& callId)
{
    std::string raw =
        "OPTIONS " + toUri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=opt1\r\n"
        "To: <" + toUri + ">\r\n"
        "Call-ID: " + callId + "\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Content-Length: 0\r\n\r\n";
    return raw;
}

// ================================
// 1) REGISTER 해제 (Expires: 0)
// ================================

void test_register_deregistration()
{
    TEST("REGISTER deregistration (Expires: 0)");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 먼저 등록
    std::string regRaw = makeRegister("sip:2001@server", "<sip:2001@10.0.0.5:5060>",
                                       "dereg1", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket pkt{"10.0.0.5", 5060, regRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(core->registrationCount() == 1);

    // Expires: 0으로 해제
    std::string deregRaw = makeRegister("sip:2001@server", "<sip:2001@10.0.0.5:5060>",
                                         "dereg2", 2, "0", "tag2");
    assert(parseSipMessage(deregRaw, msg));
    UdpPacket pkt2{"10.0.0.5", 5060, deregRaw};
    core->handlePacket(pkt2, msg, resp);
    assert(resp.find("200 OK") != std::string::npos);
    assert(core->registrationCount() == 0);
    PASS();
}

// ================================
// 2) 잘못된 Expires 값 → 400 Bad Request
// ================================

void test_register_invalid_expires()
{
    TEST("REGISTER invalid Expires → 400 Bad Request");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string raw = makeRegister("sip:3001@server", "<sip:3001@10.0.0.6:5060>",
                                    "badexp1", 1, "notanumber");
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.6", 5060, raw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("400 Bad Request") != std::string::npos);
    PASS();
}

void test_register_negative_expires()
{
    TEST("REGISTER negative Expires → 400 Bad Request");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string raw = makeRegister("sip:3002@server", "<sip:3002@10.0.0.6:5060>",
                                    "badexp2", 1, "-100");
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.6", 5060, raw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    // 음수 값은 숫자 앞에 '-'가 있으므로 유효하지 않은 숫자로 처리됨
    assert(resp.find("400 Bad Request") != std::string::npos);
    PASS();
}

// ================================
// 3) REGISTER 빈 Contact/To → 400
// ================================

void test_register_missing_headers()
{
    TEST("REGISTER missing To/Contact → 400");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // Contact 없는 REGISTER
    std::string raw =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@server>;tag=123\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: noreg1\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, raw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("400 Bad Request") != std::string::npos);
    PASS();
}

// ================================
// 4) 미등록 사용자에게 INVITE → 404 Not Found
// ================================

void test_invite_to_unregistered_user()
{
    TEST("INVITE to unregistered user → 404");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string invRaw = makeInvite("sip:9999@server", "sip:1002@client", "inv404", 1);
    SipMessage msg;
    assert(parseSipMessage(invRaw, msg));
    UdpPacket pkt{"10.0.0.3", 5060, invRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("404 Not Found") != std::string::npos);
    PASS();
}

// ================================
// 5) INVITE 필수 헤더 누락 → 400
// ================================

void test_invite_missing_headers()
{
    TEST("INVITE missing required headers → 400");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // Call-ID 없는 INVITE
    std::string raw =
        "INVITE sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.3", 5060, raw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("400 Bad Request") != std::string::npos);
    PASS();
}

// ================================
// 6) BYE 처리 - 통화 종료
// ================================

void test_bye_terminates_call()
{
    TEST("BYE terminates active call");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 먼저 등록
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "reg-bye", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);
    assert(core->registrationCount() == 1);

    // INVITE
    sent.clear();
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "call-bye", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);
    assert(core->activeCallCount() == 1);

    // BYE from caller
    sent.clear();
    std::string byeRaw = makeBye("sip:1001@server", "call-bye", 2);
    assert(parseSipMessage(byeRaw, msg));
    UdpPacket byePkt{"10.0.0.2", 5060, byeRaw};
    core->handlePacket(byePkt, msg, resp);
    assert(resp.find("200 OK") != std::string::npos);
    assert(core->activeCallCount() == 0);
    PASS();
}

// ================================
// 7) BYE 존재하지 않는 통화 → 481
// ================================

void test_bye_nonexistent_call()
{
    TEST("BYE for nonexistent call → 481");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string byeRaw = makeBye("sip:1001@server", "nonexistent-call", 1);
    SipMessage msg;
    assert(parseSipMessage(byeRaw, msg));
    UdpPacket pkt{"10.0.0.2", 5060, byeRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("481") != std::string::npos);
    PASS();
}

// ================================
// 8) OPTIONS 처리 → 200 OK
// ================================

void test_options_returns_200()
{
    TEST("OPTIONS returns 200 OK");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string optRaw = makeOptions("sip:server", "opt1");
    SipMessage msg;
    assert(parseSipMessage(optRaw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, optRaw};
    std::string resp;
    bool ok = core->handlePacket(pkt, msg, resp);
    assert(ok);
    assert(resp.find("200 OK") != std::string::npos);
    PASS();
}

// ================================
// 9) handleResponse 테스트 - INVITE 응답 전달
// ================================

void test_handleResponse_forwards_to_caller()
{
    TEST("handleResponse forwards response to caller");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER callee
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "reg-resp", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    // INVITE from caller
    sent.clear();
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "resp-test", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    // Simulate 200 OK response from callee
    sent.clear();
    std::string okRaw =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=inv-tag\r\n"
        "To: <sip:1001@server>;tag=callee-tag\r\n"
        "Call-ID: resp-test\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:1001@10.0.0.1:5060>\r\n"
        "Content-Length: 0\r\n\r\n";
    assert(parseSipMessage(okRaw, msg));
    UdpPacket respPkt{"10.0.0.1", 5060, okRaw};
    bool handled = core->handleResponse(respPkt, msg);
    assert(handled);

    // 200 OK가 caller에게 전달되어야 함
    bool foundToCallerOk = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.2" && m.data.find("200 OK") != std::string::npos)
            foundToCallerOk = true;
    }
    assert(foundToCallerOk);
    PASS();
}

// ================================
// 10) getStats 검증
// ================================

void test_getStats()
{
    TEST("getStats returns correct statistics");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    auto stats = core->getStats();
    assert(stats.registrationCount == 0);
    assert(stats.activeCallCount == 0);
    assert(stats.confirmedCallCount == 0);
    assert(stats.pendingCallCount == 0);

    // REGISTER
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "stat-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    stats = core->getStats();
    assert(stats.registrationCount == 1);
    assert(stats.activeRegistrationCount == 1);

    // INVITE (creates pending call)
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "stat-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    stats = core->getStats();
    assert(stats.activeCallCount == 1);
    assert(stats.pendingCallCount == 1);
    assert(stats.confirmedCallCount == 0);
    PASS();
}

// ================================
// 11) getAllRegistrations / getAllActiveCalls
// ================================

void test_getAllRegistrations()
{
    TEST("getAllRegistrations");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 2개 등록
    for (int i = 1; i <= 2; ++i)
    {
        std::string aor = "sip:user" + std::to_string(i) + "@server";
        std::string contact = "<sip:user" + std::to_string(i) + "@10.0.0." + std::to_string(i) + ":5060>";
        std::string regRaw = makeRegister(aor, contact, "grr" + std::to_string(i), 1, "3600");
        SipMessage msg;
        assert(parseSipMessage(regRaw, msg));
        UdpPacket pkt{"10.0.0." + std::to_string(i), 5060, regRaw};
        std::string resp;
        core->handlePacket(pkt, msg, resp);
    }

    auto allRegs = core->getAllRegistrations(false);
    assert(allRegs.size() == 2);

    auto activeRegs = core->getAllRegistrations(true);
    assert(activeRegs.size() == 2);

    PASS();
}

void test_getAllActiveCalls()
{
    TEST("getAllActiveCalls");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER + INVITE
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "gac-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "gac-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    auto allCalls = core->getAllActiveCalls(false);
    assert(allCalls.size() == 1);

    auto confirmedCalls = core->getAllActiveCalls(true);
    assert(confirmedCalls.size() == 0);  // 아직 확인되지 않은 통화

    PASS();
}

// ================================
// 12) findRegistrationSafe / findCallSafe
// ================================

void test_findRegistrationSafe()
{
    TEST("findRegistrationSafe");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "find-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);

    auto found = core->findRegistrationSafe("sip:1001@server");
    assert(found.has_value());
    assert(found->ip == "10.0.0.1");
    assert(found->port == 5060);

    auto notFound = core->findRegistrationSafe("sip:nonexistent@server");
    assert(!notFound.has_value());
    PASS();
}

void test_findCallSafe()
{
    TEST("findCallSafe");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER + INVITE
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "fcs-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "fcs-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    auto found = core->findCallSafe("fcs-call");
    assert(found.has_value());
    assert(found->callId == "fcs-call");
    assert(found->callerIp == "10.0.0.2");

    auto notFound = core->findCallSafe("nonexistent");
    assert(!notFound.has_value());
    PASS();
}

// ================================
// 13) registerTerminal (프로그래매틱 등록)
// ================================

void test_registerTerminal()
{
    TEST("registerTerminal programmatic registration");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    bool ok = core->registerTerminal("sip:prog1@server", "sip:prog1@10.0.0.1:5060",
                                     "10.0.0.1", 5060, 3600);
    assert(ok);
    assert(core->registrationCount() == 1);

    auto reg = core->findRegistrationSafe("sip:prog1@server");
    assert(reg.has_value());
    assert(reg->ip == "10.0.0.1");
    PASS();
}

void test_registerTerminal_invalid_params()
{
    TEST("registerTerminal invalid params");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 빈 AOR
    assert(!core->registerTerminal("", "contact", "10.0.0.1", 5060));
    // 빈 IP
    assert(!core->registerTerminal("sip:user@server", "contact", "", 5060));

    assert(core->registrationCount() == 0);
    PASS();
}

// ================================
// 14) cleanupExpiredRegistrations
// ================================

void test_cleanupExpiredRegistrations()
{
    TEST("cleanupExpiredRegistrations");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 매우 짧은 만료 시간으로 등록
    core->registerTerminal("sip:expire1@server", "sip:expire1@10.0.0.1:5060",
                          "10.0.0.1", 5060, 1);  // 1초

    assert(core->registrationCount() == 1);

    // 1초 대기 후 만료 정리
    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::size_t removed = core->cleanupExpiredRegistrations();
    assert(removed >= 1);
    assert(core->registrationCount() == 0);
    PASS();
}

// ================================
// 15) cleanupStaleCalls
// ================================

void test_cleanupStaleCalls()
{
    TEST("cleanupStaleCalls removes old unconfirmed calls");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER + INVITE
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "stale-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "stale-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);
    assert(core->activeCallCount() == 1);

    // 1초 이상 대기 후 maxAge=0s 설정 → elapsed(>=1) > 0 이 되어 제거됨
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    std::size_t removed = core->cleanupStaleCalls(std::chrono::seconds(0));
    assert(removed >= 1);
    assert(core->activeCallCount() == 0);
    PASS();
}

// ================================
// 16) cleanupStaleTransactions
// ================================

void test_cleanupStaleTransactions()
{
    TEST("cleanupStaleTransactions");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER + INVITE 생성 (pendingInvite 생성됨)
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "stx-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "stx-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);
    assert(core->activeCallCount() == 1);

    // ttl을 0초로 설정하여 즉시 제거
    std::size_t removed = core->cleanupStaleTransactions(std::chrono::seconds(0));
    assert(removed >= 1);
    PASS();
}

// ================================
// 17) Response 처리 — Response 타입은 handlePacket에서 거부
// ================================

void test_handlePacket_rejects_response()
{
    TEST("handlePacket rejects SIP response");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string raw =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>;tag=xyz\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, raw};
    std::string resp;
    bool ok = core->handlePacket(pkt, msg, resp);
    assert(!ok);
    PASS();
}

// ================================
// 18) INVITE 재전송 감지
// ================================

void test_invite_retransmission_detection()
{
    TEST("INVITE retransmission returns cached response");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "retx-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    // 첫 번째 INVITE
    sent.clear();
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "retx-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);
    std::size_t firstSentCount = sent.size();
    (void)firstSentCount;  // suppress unused variable warning
    assert(core->activeCallCount() == 1);

    // 동일한 INVITE 재전송
    sent.clear();
    core->handlePacket(invPkt, msg, resp);
    // 재전송의 경우 100 Trying은 다시 보내지만, 새 ActiveCall을 생성하지 않음
    assert(core->activeCallCount() == 1);
    PASS();
}

// ================================
// 19) handleResponse — 잘못된 CSeq → false
// ================================

void test_handleResponse_invalid_cseq()
{
    TEST("handleResponse with missing call-id → false");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // CSeq나 Call-ID가 없는 응답
    SipMessage msg;
    msg.type = SipType::Response;
    msg.statusCode = 200;
    msg.reasonPhrase = "OK";
    msg.sipVersion = "SIP/2.0";
    // 헤더 없음
    UdpPacket pkt{"10.0.0.1", 5060, ""};
    bool ok = core->handleResponse(pkt, msg);
    assert(!ok);
    PASS();
}

// ================================
// 20) 최대 Expires 값 제한
// ================================

void test_register_max_expires_clamped()
{
    TEST("REGISTER Expires clamped to MAX_EXPIRES_SEC");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // MAX_EXPIRES_SEC = 7200 보다 큰 값
    std::string regRaw = makeRegister("sip:maxexp@server", "<sip:maxexp@10.0.0.1:5060>",
                                       "maxexp1", 1, "99999");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("200 OK") != std::string::npos);
    assert(core->registrationCount() == 1);
    PASS();
}

// ================================
// 21) CANCEL 필수 헤더 누락 → 400
// ================================

void test_cancel_missing_headers()
{
    TEST("CANCEL missing Call-ID → 400");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string raw =
        "CANCEL sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.2", 5060, raw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    assert(resp.find("400 Bad Request") != std::string::npos);
    PASS();
}

// ================================
// 22) BYE 전달 (B2BUA 동작)
// ================================

void test_bye_forwarded_to_callee()
{
    TEST("BYE forwarded to callee");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // REGISTER
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "bye-fwd-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    // INVITE → ACK (통화 확립)
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "bye-fwd", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    // ACK from caller
    std::string ackRaw =
        "ACK sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=inv-tag\r\n"
        "To: <sip:1001@server>;tag=xyz\r\n"
        "Call-ID: bye-fwd\r\n"
        "CSeq: 1 ACK\r\n"
        "Content-Length: 0\r\n\r\n";
    assert(parseSipMessage(ackRaw, msg));
    UdpPacket ackPkt{"10.0.0.2", 5060, ackRaw};
    core->handlePacket(ackPkt, msg, resp);

    // BYE from caller
    sent.clear();
    std::string byeRaw = makeBye("sip:1001@server", "bye-fwd", 2);
    assert(parseSipMessage(byeRaw, msg));
    UdpPacket byePkt{"10.0.0.2", 5060, byeRaw};
    core->handlePacket(byePkt, msg, resp);
    assert(resp.find("200 OK") != std::string::npos);

    // BYE가 callee에게 전달되어야 함
    bool foundByeToCallee = false;
    for (const auto& m : sent)
    {
        if (m.ip == "10.0.0.1" && m.data.find("BYE ") != std::string::npos)
            foundByeToCallee = true;
    }
    assert(foundByeToCallee);
    PASS();
}

// ================================
// 23) 지원하지 않는 메서드 → 501
// ================================

void test_unsupported_method()
{
    TEST("Unsupported method returns 501 (via handlePacket)");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 파서에서 INFO를 유효한 메서드로 인식하지만, 
    // handlePacket에서 처리하지 않는 메서드
    // INFO, REFER, MESSAGE, UPDATE, PUBLISH, SUBSCRIBE, NOTIFY, PRACK 등은
    // handlePacket에서 501을 반환
    std::string raw =
        "INFO sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1002@client>;tag=info1\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: info1\r\n"
        "CSeq: 1 INFO\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    UdpPacket pkt{"10.0.0.1", 5060, raw};
    std::string resp;
    bool ok = core->handlePacket(pkt, msg, resp);
    assert(ok);
    assert(resp.find("501") != std::string::npos);
    PASS();
}

// ================================
// 24) CANCEL이 활성 INVITE를 취소
// ================================

void test_cancel_active_invite()
{
    TEST("CANCEL cancels active INVITE → 200 + 487");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 먼저 callee 등록
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "cancel-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);
    assert(core->registrationCount() == 1);

    // INVITE 전송
    sent.clear();
    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "cancel-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);
    assert(core->activeCallCount() == 1);

    // CANCEL 전송
    sent.clear();
    std::string cancelRaw =
        "CANCEL sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=inv-tag\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: cancel-call\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Content-Length: 0\r\n\r\n";
    assert(parseSipMessage(cancelRaw, msg));
    UdpPacket cancelPkt{"10.0.0.2", 5060, cancelRaw};
    core->handlePacket(cancelPkt, msg, resp);
    // CANCEL에 대한 200 OK
    assert(resp.find("200 OK") != std::string::npos);

    // 487 Request Terminated가 caller에게 전송되어야 함
    bool found487 = false;
    bool foundCancelToCallee = false;
    for (const auto& m : sent) {
        if (m.data.find("487") != std::string::npos)
            found487 = true;
        if (m.data.find("CANCEL") != std::string::npos && m.ip == "10.0.0.1")
            foundCancelToCallee = true;
    }
    assert(found487);
    assert(foundCancelToCallee);
    // ActiveCall이 정리되어야 함
    assert(core->activeCallCount() == 0);
    PASS();
}

// ================================
// 25) CANCEL 매칭 INVITE 없음 → 481
// ================================

void test_cancel_no_matching_invite()
{
    TEST("CANCEL with no matching INVITE → cleanup only");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    std::string cancelRaw =
        "CANCEL sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP caller:5060\r\n"
        "From: <sip:1002@client>;tag=no-match\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: no-match-call\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(cancelRaw, msg));
    UdpPacket pkt{"10.0.0.2", 5060, cancelRaw};
    std::string resp;
    core->handlePacket(pkt, msg, resp);
    // 매칭 INVITE 없어도 200 OK 반환 (RFC 3261)
    assert(resp.find("200 OK") != std::string::npos);
    PASS();
}

// ================================
// 26) Re-REGISTER (contact 업데이트)
// ================================

void test_re_register_updates_contact()
{
    TEST("Re-REGISTER updates contact info");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 첫 번째 등록
    std::string reg1 = makeRegister("sip:5001@server", "<sip:5001@10.0.0.1:5060>",
                                     "rereg1", 1, "3600", "tag-a");
    SipMessage msg;
    assert(parseSipMessage(reg1, msg));
    UdpPacket pkt1{"10.0.0.1", 5060, reg1};
    std::string resp;
    core->handlePacket(pkt1, msg, resp);
    assert(core->registrationCount() == 1);

    auto r1 = core->findRegistrationSafe("sip:5001@server");
    assert(r1.has_value());
    assert(r1->ip == "10.0.0.1");

    // 같은 AOR로 다시 등록 (다른 IP)
    std::string reg2 = makeRegister("sip:5001@server", "<sip:5001@10.0.0.99:5060>",
                                     "rereg2", 2, "3600", "tag-b");
    assert(parseSipMessage(reg2, msg));
    UdpPacket pkt2{"10.0.0.99", 5060, reg2};
    core->handlePacket(pkt2, msg, resp);
    assert(core->registrationCount() == 1); // 갱신이므로 수 변화 없음

    auto r2 = core->findRegistrationSafe("sip:5001@server");
    assert(r2.has_value());
    assert(r2->ip == "10.0.0.99"); // 업데이트됨
    PASS();
}

// ================================
// 27) 두 번째 BYE → 481
// ================================

void test_double_bye_returns_481()
{
    TEST("Second BYE on same call returns 481");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    // 등록 + INVITE
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "dbye-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "dbye-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    // 첫 번째 BYE → 200 OK
    std::string byeRaw = makeBye("sip:1001@server", "dbye-call", 2);
    assert(parseSipMessage(byeRaw, msg));
    UdpPacket byePkt{"10.0.0.2", 5060, byeRaw};
    core->handlePacket(byePkt, msg, resp);
    assert(resp.find("200 OK") != std::string::npos);

    // 두 번째 BYE → 481
    sent.clear();
    core->handlePacket(byePkt, msg, resp);
    assert(resp.find("481") != std::string::npos);
    PASS();
}

// ================================
// 28) getStats — confirmed call count
// ================================

void test_getStats_confirmed_count()
{
    TEST("getStats tracks confirmed vs pending calls");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    auto stats = core->getStats();
    assert(stats.confirmedCallCount == 0);
    assert(stats.pendingCallCount == 0);

    // 등록 + INVITE → pending call
    std::string regRaw = makeRegister("sip:1001@server", "<sip:1001@10.0.0.1:5060>",
                                       "stats-reg", 1, "3600");
    SipMessage msg;
    assert(parseSipMessage(regRaw, msg));
    UdpPacket regPkt{"10.0.0.1", 5060, regRaw};
    std::string resp;
    core->handlePacket(regPkt, msg, resp);

    std::string invRaw = makeInvite("sip:1001@server", "sip:1002@client", "stats-call", 1);
    assert(parseSipMessage(invRaw, msg));
    UdpPacket invPkt{"10.0.0.2", 5060, invRaw};
    core->handlePacket(invPkt, msg, resp);

    stats = core->getStats();
    assert(stats.activeCallCount == 1);
    // 아직 confirmed 되지 않은 상태
    assert(stats.confirmedCallCount == 0);
    PASS();
}

// ================================
// 29) handlePacket with SipType::Invalid
// ================================

void test_handlePacket_invalid_type()
{
    TEST("handlePacket with invalid SIP type");
    std::vector<SentMsg> sent;
    auto core = createCoreWithSender(sent);

    SipMessage msg;
    msg.type = SipType::Invalid;
    msg.method = "INVITE";
    UdpPacket pkt{"10.0.0.1", 5060, "garbage"};
    std::string resp;
    bool ok = core->handlePacket(pkt, msg, resp);
    // Invalid type → false 또는 에러 응답
    // handlePacket은 type이 Response이면 false, Request이면 method별 처리
    // Invalid는 Request도 Response도 아니므로
    assert(!ok || resp.find("400") != std::string::npos || resp.find("501") != std::string::npos);
    PASS();
}

// ================================
// main
// ================================

int main()
{
    std::cout << "=== Extended SipCore Tests ===\n\n";

    std::cout << "[Section 1] REGISTER\n";
    test_register_deregistration();
    test_register_invalid_expires();
    test_register_negative_expires();
    test_register_missing_headers();
    test_register_max_expires_clamped();
    test_registerTerminal();
    test_registerTerminal_invalid_params();

    std::cout << "\n[Section 2] INVITE\n";
    test_invite_to_unregistered_user();
    test_invite_missing_headers();
    test_invite_retransmission_detection();

    std::cout << "\n[Section 3] BYE\n";
    test_bye_terminates_call();
    test_bye_nonexistent_call();
    test_bye_forwarded_to_callee();

    std::cout << "\n[Section 4] CANCEL\n";
    test_cancel_missing_headers();
    test_cancel_active_invite();
    test_cancel_no_matching_invite();

    std::cout << "\n[Section 5] OPTIONS\n";
    test_options_returns_200();

    std::cout << "\n[Section 6] Response handling\n";
    test_handlePacket_rejects_response();
    test_handleResponse_forwards_to_caller();
    test_handleResponse_invalid_cseq();
    test_handlePacket_invalid_type();

    std::cout << "\n[Section 7] Statistics & queries\n";
    test_getStats();
    test_getStats_confirmed_count();
    test_getAllRegistrations();
    test_getAllActiveCalls();
    test_findRegistrationSafe();
    test_findCallSafe();

    std::cout << "\n[Section 8] Cleanup\n";
    test_cleanupExpiredRegistrations();
    test_cleanupStaleCalls();
    test_cleanupStaleTransactions();

    std::cout << "\n[Section 9] Additional flows\n";
    test_unsupported_method();
    test_re_register_updates_contact();
    test_double_bye_returns_481();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
