#include "SipParser.h"
#include "SipCore.h"
#include "SipUtils.h"
#include <cassert>
#include <iostream>
#include <string>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

#define FAIL(reason) \
    do { std::cout << "FAILED: " << reason << "\n"; ++testsFailed; } while(0)

// ================================
// 1) 빈 / 비정상 입력 테스트
// ================================

void test_empty_input()
{
    TEST("Empty input");
    SipMessage msg;
    assert(!parseSipMessage("", msg));
    PASS();
}

void test_only_whitespace()
{
    TEST("Only whitespace");
    SipMessage msg;
    assert(!parseSipMessage("   \r\n  ", msg));
    PASS();
}

void test_no_crlf_terminator()
{
    TEST("No CRLF CRLF terminator");
    SipMessage msg;
    // 헤더-바디 구분자 없는 메시지
    assert(!parseSipMessage("INVITE sip:user@server SIP/2.0\r\nVia: SIP/2.0/UDP client:5060\r\n", msg));
    PASS();
}

void test_garbage_input()
{
    TEST("Garbage input");
    SipMessage msg;
    assert(!parseSipMessage("this is not a SIP message at all\r\n\r\n", msg));
    PASS();
}

void test_empty_first_line()
{
    TEST("Empty first line");
    SipMessage msg;
    assert(!parseSipMessage("\r\nVia: SIP/2.0/UDP client:5060\r\n\r\n", msg));
    PASS();
}

// ================================
// 2) 다양한 SIP 메서드 파싱
// ================================

void test_register_parse()
{
    TEST("REGISTER request parsing");
    std::string raw =
        "REGISTER sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@server>;tag=abc\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: reg123\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Contact: <sip:1001@10.0.0.1:5060>\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.type == SipType::Request);
    assert(msg.method == "REGISTER");
    assert(msg.requestUri == "sip:server");
    assert(msg.sipVersion == "SIP/2.0");
    PASS();
}

void test_bye_parse()
{
    TEST("BYE request parsing");
    std::string raw =
        "BYE sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1002@client>;tag=xyz\r\n"
        "To: <sip:1001@server>;tag=abc\r\n"
        "Call-ID: bye123\r\n"
        "CSeq: 2 BYE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.type == SipType::Request);
    assert(msg.method == "BYE");
    assert(msg.requestUri == "sip:1001@server");
    PASS();
}

void test_cancel_parse()
{
    TEST("CANCEL request parsing");
    std::string raw =
        "CANCEL sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1002@client>;tag=xyz\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: cancel123\r\n"
        "CSeq: 1 CANCEL\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.method == "CANCEL");
    PASS();
}

void test_ack_parse()
{
    TEST("ACK request parsing");
    std::string raw =
        "ACK sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1002@client>;tag=abc\r\n"
        "To: <sip:1001@server>;tag=xyz\r\n"
        "Call-ID: ack123\r\n"
        "CSeq: 1 ACK\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.method == "ACK");
    PASS();
}

void test_options_parse()
{
    TEST("OPTIONS request parsing");
    std::string raw =
        "OPTIONS sip:server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:server>\r\n"
        "Call-ID: opt123\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.method == "OPTIONS");
    PASS();
}

void test_subscribe_parse()
{
    TEST("SUBSCRIBE request parsing");
    std::string raw =
        "SUBSCRIBE sip:1001@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1002@client>;tag=sub1\r\n"
        "To: <sip:1001@server>\r\n"
        "Call-ID: sub123\r\n"
        "CSeq: 1 SUBSCRIBE\r\n"
        "Event: presence\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.method == "SUBSCRIBE");
    PASS();
}

// ================================
// 3) 잘못된 메서드/버전/URI
// ================================

void test_invalid_method()
{
    TEST("Invalid method rejected");
    std::string raw =
        "FOOBAR sip:user@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_invalid_sip_version()
{
    TEST("Invalid SIP version rejected");
    std::string raw =
        "INVITE sip:user@server SIP/3.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_http_version_rejected()
{
    TEST("HTTP version rejected");
    std::string raw =
        "INVITE sip:user@server HTTP/1.1\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_invalid_request_uri()
{
    TEST("Invalid request URI rejected");
    std::string raw =
        "INVITE http://user@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

// ================================
// 4) 다양한 응답 상태 코드 파싱
// ================================

void test_100_trying_response()
{
    TEST("100 Trying response");
    std::string raw =
        "SIP/2.0 100 Trying\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.type == SipType::Response);
    assert(msg.statusCode == 100);
    assert(msg.reasonPhrase == "Trying");
    PASS();
}

void test_180_ringing_response()
{
    TEST("180 Ringing response");
    std::string raw =
        "SIP/2.0 180 Ringing\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>;tag=xyz\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.statusCode == 180);
    PASS();
}

void test_404_not_found_response()
{
    TEST("404 Not Found response");
    std::string raw =
        "SIP/2.0 404 Not Found\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>;tag=xyz\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.statusCode == 404);
    assert(msg.reasonPhrase == "Not Found");
    PASS();
}

void test_486_busy_here_response()
{
    TEST("486 Busy Here response");
    std::string raw =
        "SIP/2.0 486 Busy Here\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>;tag=xyz\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.statusCode == 486);
    PASS();
}

void test_500_server_error_response()
{
    TEST("500 Server Internal Error response");
    std::string raw =
        "SIP/2.0 500 Server Internal Error\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>;tag=xyz\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.statusCode == 500);
    PASS();
}

void test_invalid_status_code_99()
{
    TEST("Invalid status code 99 rejected");
    std::string raw =
        "SIP/2.0 99 Too Low\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_invalid_status_code_700()
{
    TEST("Invalid status code 700 rejected");
    std::string raw =
        "SIP/2.0 700 Too High\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

// ================================
// 5) 헤더 파싱 상세 검증
// ================================

void test_header_case_insensitive()
{
    TEST("Header names stored lowercase");
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: abc123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));

    // 헤더는 소문자로 저장됨
    assert(msg.headers.find("via") != msg.headers.end());
    assert(msg.headers.find("from") != msg.headers.end());
    assert(msg.headers.find("to") != msg.headers.end());
    assert(msg.headers.find("call-id") != msg.headers.end());
    assert(msg.headers.find("cseq") != msg.headers.end());
    assert(msg.headers.find("content-length") != msg.headers.end());

    // getHeader로 대소문자 무관 조회
    assert(getHeader(msg, "Via") == getHeader(msg, "via"));
    assert(getHeader(msg, "FROM") == getHeader(msg, "from"));
    PASS();
}

void test_header_continuation_line()
{
    TEST("Header continuation line (folding)");
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP\r\n"
        " client.example.com:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: fold123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    // Via 헤더에 연속 줄이 포함되어야 함
    std::string via = getHeader(msg, "via");
    assert(via.find("SIP/2.0/UDP") != std::string::npos);
    assert(via.find("client.example.com") != std::string::npos);
    PASS();
}

void test_duplicate_headers_combined()
{
    TEST("Duplicate headers combined with comma");
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP proxy1:5060\r\n"
        "Via: SIP/2.0/UDP proxy2:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: dup123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    std::string via = getHeader(msg, "via");
    // RFC 3261: 동일 이름 헤더는 콤마로 결합
    assert(via.find("proxy1") != std::string::npos);
    assert(via.find("proxy2") != std::string::npos);
    PASS();
}

void test_get_all_headers()
{
    TEST("getAllHeaders separates comma-combined values");
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP proxy1:5060\r\n"
        "Via: SIP/2.0/UDP proxy2:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: multi123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    auto vias = getAllHeaders(msg, "via");
    assert(vias.size() == 2);
    assert(vias[0].find("proxy1") != std::string::npos);
    assert(vias[1].find("proxy2") != std::string::npos);
    PASS();
}

// ================================
// 6) SDP Body 포함 메시지 파싱
// ================================

void test_invite_with_sdp_body()
{
    TEST("INVITE with SDP body");
    std::string sdp =
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 198.51.100.1\r\n"
        "s=-\r\n"
        "c=IN IP4 198.51.100.1\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 0 8 97\r\n";

    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: sdp123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;

    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.type == SipType::Request);
    assert(msg.method == "INVITE");
    assert(msg.body == sdp);
    assert(getHeader(msg, "content-type") == "application/sdp");
    PASS();
}

// ================================
// 7) 보안 관련 테스트
// ================================

void test_oversized_message_rejected()
{
    TEST("Oversized message rejected");
    // MAX_MESSAGE_SIZE = 64KB를 초과하는 메시지
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: big123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    raw += std::string(65 * 1024, 'A');  // 65KB body
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_too_many_headers_rejected()
{
    TEST("Too many headers rejected");
    std::string raw = "INVITE sip:1000@server SIP/2.0\r\n";
    // MAX_HEADERS_COUNT = 100을 초과
    for (int i = 0; i < 110; ++i)
    {
        raw += "X-Custom-Header-" + std::to_string(i) + ": value" + std::to_string(i) + "\r\n";
    }
    raw += "\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_sips_uri_accepted()
{
    TEST("sips: URI accepted");
    std::string raw =
        "INVITE sips:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=123\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: sips123\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.requestUri == "sips:1000@server");
    PASS();
}

// ================================
// 8) 추가 파서 엣지케이스 테스트
// ================================

void test_content_length_mismatch_still_parses()
{
    TEST("Content-Length mismatch still parses");
    // 파서는 Content-Length와 실제 body 크기 불일치를 검증하지 않음
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=abc\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: clmismatch1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 100\r\n\r\n"
        "short body";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.body == "short body");
    PASS();
}

void test_header_with_empty_value()
{
    TEST("Header with empty value");
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=abc\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: emptyval1\r\n"
        "CSeq: 1 INVITE\r\n"
        "X-Custom:\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    // 빈 값 헤더도 파싱 성공
    assert(getHeader(msg, "x-custom") == "");
    PASS();
}

void test_response_with_empty_reason_phrase()
{
    TEST("Response with empty reason phrase");
    std::string raw =
        "SIP/2.0 200 \r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=abc\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: emptyrsn1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(parseSipMessage(raw, msg));
    assert(msg.type == SipType::Response);
    assert(msg.statusCode == 200);
    PASS();
}

void test_null_byte_in_request_uri()
{
    TEST("Null byte in request URI rejected");
    // Request-URI에 null byte가 포함되면 isValidRequestUri가 false
    std::string uri = std::string("sip:user\0@server", 16);
    std::string raw =
        "INVITE " + uri + " SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=abc\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: null1\r\n"
        "CSeq: 1 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_crlf_only_message()
{
    TEST("CRLF-only message rejected");
    SipMessage msg;
    assert(!parseSipMessage("\r\n\r\n", msg));
    PASS();
}

void test_max_body_size_rejected()
{
    TEST("Body exceeding MAX_BODY_SIZE rejected");
    std::string body(65 * 1024, 'B');
    std::string raw =
        "MESSAGE sip:1000@server SIP/2.0\r\n"
        "Via: SIP/2.0/UDP client:5060\r\n"
        "From: <sip:1001@client>;tag=abc\r\n"
        "To: <sip:1000@server>\r\n"
        "Call-ID: bigbody1\r\n"
        "CSeq: 1 MESSAGE\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

void test_header_portion_exceeds_limit()
{
    TEST("Header portion exceeds MAX_HEADER_SIZE");
    // MAX_HEADER_SIZE = 8KB
    std::string longHeaderValue(8 * 1024, 'H');
    std::string raw =
        "INVITE sip:1000@server SIP/2.0\r\n"
        "X-Long: " + longHeaderValue + "\r\n"
        "Content-Length: 0\r\n\r\n";
    SipMessage msg;
    assert(!parseSipMessage(raw, msg));
    PASS();
}

// ================================
// main
// ================================

int main()
{
    std::cout << "=== Extended Parser Tests ===\n\n";

    // 1) 빈/비정상 입력
    std::cout << "[Section 1] Invalid inputs\n";
    test_empty_input();
    test_only_whitespace();
    test_no_crlf_terminator();
    test_garbage_input();
    test_empty_first_line();

    // 2) 다양한 메서드
    std::cout << "\n[Section 2] Various SIP methods\n";
    test_register_parse();
    test_bye_parse();
    test_cancel_parse();
    test_ack_parse();
    test_options_parse();
    test_subscribe_parse();

    // 3) 잘못된 메서드/버전/URI
    std::cout << "\n[Section 3] Invalid method/version/URI\n";
    test_invalid_method();
    test_invalid_sip_version();
    test_http_version_rejected();
    test_invalid_request_uri();

    // 4) 다양한 응답 코드
    std::cout << "\n[Section 4] Various response codes\n";
    test_100_trying_response();
    test_180_ringing_response();
    test_404_not_found_response();
    test_486_busy_here_response();
    test_500_server_error_response();
    test_invalid_status_code_99();
    test_invalid_status_code_700();

    // 5) 헤더 상세 검증
    std::cout << "\n[Section 5] Header parsing details\n";
    test_header_case_insensitive();
    test_header_continuation_line();
    test_duplicate_headers_combined();
    test_get_all_headers();

    // 6) SDP Body
    std::cout << "\n[Section 6] SDP body\n";
    test_invite_with_sdp_body();

    // 7) 보안
    std::cout << "\n[Section 7] Security\n";
    test_oversized_message_rejected();
    test_too_many_headers_rejected();
    test_sips_uri_accepted();

    // 8) 추가 파서 엣지케이스
    std::cout << "\n[Section 8] Additional parser edge cases\n";
    test_content_length_mismatch_still_parses();
    test_header_with_empty_value();
    test_response_with_empty_reason_phrase();
    test_null_byte_in_request_uri();
    test_crlf_only_message();
    test_max_body_size_rejected();
    test_header_portion_exceeds_limit();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
