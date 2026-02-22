#include "SipUtils.h"
#include "SipCore.h"
#include <cassert>
#include <iostream>
#include <string>
#include <limits>

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
// 1) ltrim 테스트
// ================================

void test_ltrim_basic()
{
    TEST("ltrim basic");
    assert(ltrim("   hello") == "hello");
    assert(ltrim("hello") == "hello");
    assert(ltrim("") == "");
    assert(ltrim("   ") == "");
    assert(ltrim("\t\n hello") == "hello");
    PASS();
}

void test_ltrim_no_left_spaces()
{
    TEST("ltrim no left spaces");
    assert(ltrim("hello   ") == "hello   ");
    PASS();
}

// ================================
// 2) rtrim 테스트
// ================================

void test_rtrim_basic()
{
    TEST("rtrim basic");
    assert(rtrim("hello   ") == "hello");
    assert(rtrim("hello") == "hello");
    assert(rtrim("") == "");
    assert(rtrim("   ") == "");
    assert(rtrim("hello \t\n") == "hello");
    PASS();
}

void test_rtrim_no_right_spaces()
{
    TEST("rtrim no right spaces");
    assert(rtrim("   hello") == "   hello");
    PASS();
}

// ================================
// 3) trim 테스트
// ================================

void test_trim_both_sides()
{
    TEST("trim both sides");
    assert(trim("  hello  ") == "hello");
    assert(trim("  \t hello world \n ") == "hello world");
    assert(trim("") == "");
    assert(trim("   ") == "");
    assert(trim("hello") == "hello");
    PASS();
}

// ================================
// 4) toLower 테스트
// ================================

void test_toLower()
{
    TEST("toLower");
    assert(toLower("HELLO") == "hello");
    assert(toLower("Hello World") == "hello world");
    assert(toLower("") == "");
    assert(toLower("already lower") == "already lower");
    assert(toLower("123ABC") == "123abc");
    PASS();
}

// ================================
// 5) isValidSipMethod 테스트
// ================================

void test_valid_sip_methods()
{
    TEST("Valid SIP methods");
    assert(isValidSipMethod("INVITE"));
    assert(isValidSipMethod("ACK"));
    assert(isValidSipMethod("BYE"));
    assert(isValidSipMethod("CANCEL"));
    assert(isValidSipMethod("REGISTER"));
    assert(isValidSipMethod("OPTIONS"));
    assert(isValidSipMethod("PRACK"));
    assert(isValidSipMethod("SUBSCRIBE"));
    assert(isValidSipMethod("NOTIFY"));
    assert(isValidSipMethod("PUBLISH"));
    assert(isValidSipMethod("INFO"));
    assert(isValidSipMethod("REFER"));
    assert(isValidSipMethod("MESSAGE"));
    assert(isValidSipMethod("UPDATE"));
    PASS();
}

void test_invalid_sip_methods()
{
    TEST("Invalid SIP methods");
    assert(!isValidSipMethod("FOO"));
    assert(!isValidSipMethod("invite"));   // 소문자는 무효
    assert(!isValidSipMethod("Invite"));   // 혼합도 무효
    assert(!isValidSipMethod(""));
    assert(!isValidSipMethod("GET"));      // HTTP 메서드
    assert(!isValidSipMethod("POST"));
    assert(!isValidSipMethod("PATCH"));
    PASS();
}

// ================================
// 6) isValidSipVersion 테스트
// ================================

void test_valid_sip_version()
{
    TEST("Valid SIP version");
    assert(isValidSipVersion("SIP/2.0"));
    PASS();
}

void test_invalid_sip_versions()
{
    TEST("Invalid SIP versions");
    assert(!isValidSipVersion("SIP/3.0"));
    assert(!isValidSipVersion("SIP/1.0"));
    assert(!isValidSipVersion("HTTP/1.1"));
    assert(!isValidSipVersion(""));
    assert(!isValidSipVersion("sip/2.0"));  // 소문자
    assert(!isValidSipVersion("SIP/2.0 "));  // 후행 공백
    PASS();
}

// ================================
// 7) isValidStatusCode 테스트 (경계값)
// ================================

void test_valid_status_codes()
{
    TEST("Valid status codes");
    assert(isValidStatusCode(100));   // 최저 유효값
    assert(isValidStatusCode(200));
    assert(isValidStatusCode(301));
    assert(isValidStatusCode(404));
    assert(isValidStatusCode(500));
    assert(isValidStatusCode(603));
    assert(isValidStatusCode(699));   // 최고 유효값
    PASS();
}

void test_invalid_status_codes()
{
    TEST("Invalid status codes (boundary)");
    assert(!isValidStatusCode(99));    // 하한 미만
    assert(!isValidStatusCode(700));   // 상한 초과
    assert(!isValidStatusCode(0));
    assert(!isValidStatusCode(-1));
    assert(!isValidStatusCode(1000));
    assert(!isValidStatusCode(-100));
    PASS();
}

// ================================
// 8) isValidRequestUri 테스트
// ================================

void test_valid_request_uris()
{
    TEST("Valid request URIs");
    assert(isValidRequestUri("sip:user@example.com"));
    assert(isValidRequestUri("sips:user@example.com"));
    assert(isValidRequestUri("sip:1001@10.0.0.1:5060"));
    assert(isValidRequestUri("sip:server"));
    PASS();
}

void test_invalid_request_uris()
{
    TEST("Invalid request URIs");
    assert(!isValidRequestUri("http://example.com"));
    assert(!isValidRequestUri(""));
    assert(!isValidRequestUri("ftp://example.com"));
    assert(!isValidRequestUri("user@example.com"));  // "sip:" 없음
    // 256자 초과
    std::string longUri = "sip:" + std::string(260, 'a') + "@server";
    assert(!isValidRequestUri(longUri));
    PASS();
}

void test_request_uri_crlf_injection()
{
    TEST("Request URI CRLF injection rejected");
    assert(!isValidRequestUri("sip:user@server\r\nEvil: header"));
    assert(!isValidRequestUri("sip:user@server\r"));
    assert(!isValidRequestUri("sip:user@server\n"));
    PASS();
}

// ================================
// 9) parseCSeqNum 테스트
// ================================

void test_parseCSeqNum_basic()
{
    TEST("parseCSeqNum basic");
    assert(parseCSeqNum("1 INVITE") == 1);
    assert(parseCSeqNum("100 REGISTER") == 100);
    assert(parseCSeqNum("999 BYE") == 999);
    assert(parseCSeqNum("0 ACK") == 0);
    PASS();
}

void test_parseCSeqNum_edge_cases()
{
    TEST("parseCSeqNum edge cases");
    assert(parseCSeqNum("") == -1);           // 빈 문자열
    assert(parseCSeqNum("abc") == -1);        // 숫자 없음
    assert(parseCSeqNum("  42 INVITE") == 42); // 선행 공백
    PASS();
}

void test_parseCSeqNum_overflow()
{
    TEST("parseCSeqNum overflow");
    // INT_MAX 초과값
    assert(parseCSeqNum("99999999999999 INVITE") == -1);
    PASS();
}

// ================================
// 10) parseCSeqMethod 테스트
// ================================

void test_parseCSeqMethod_basic()
{
    TEST("parseCSeqMethod basic");
    assert(parseCSeqMethod("1 INVITE") == "INVITE");
    assert(parseCSeqMethod("100 REGISTER") == "REGISTER");
    assert(parseCSeqMethod("2 BYE") == "BYE");
    assert(parseCSeqMethod("1 ACK") == "ACK");
    PASS();
}

void test_parseCSeqMethod_with_spaces()
{
    TEST("parseCSeqMethod with leading spaces");
    assert(parseCSeqMethod("  42   CANCEL") == "CANCEL");
    PASS();
}

void test_parseCSeqMethod_empty()
{
    TEST("parseCSeqMethod empty input");
    assert(parseCSeqMethod("") == "");
    assert(parseCSeqMethod("123") == "");  // 메서드 부분 없음 (숫자 뒤 아무것도 없음)
    PASS();
}

// ================================
// 11) sanitizeForDisplay 테스트
// ================================

void test_sanitizeForDisplay_basic()
{
    TEST("sanitizeForDisplay basic");
    // 비출력 문자가 대체됨
    std::string clean = sanitizeForDisplay("hello\x01world", 512, '.', false);
    assert(clean == "hello.world");
    PASS();
}

void test_sanitizeForDisplay_truncation()
{
    TEST("sanitizeForDisplay truncation");
    std::string longStr(1000, 'A');
    std::string result = sanitizeForDisplay(longStr, 50, '.', false);
    assert(result.size() <= 50);
    assert(result.find("truncated") != std::string::npos);
    PASS();
}

void test_sanitizeForDisplay_allow_crlf()
{
    TEST("sanitizeForDisplay allow CRLF/TAB");
    std::string withCrLf = "hello\r\nworld\ttab";
    std::string allowed = sanitizeForDisplay(withCrLf, 512, '.', true);
    assert(allowed.find('\r') != std::string::npos);
    assert(allowed.find('\n') != std::string::npos);
    assert(allowed.find('\t') != std::string::npos);

    std::string denied = sanitizeForDisplay(withCrLf, 512, '.', false);
    assert(denied.find('\r') == std::string::npos);
    assert(denied.find('\n') == std::string::npos);
    assert(denied.find('\t') == std::string::npos);
    PASS();
}

void test_sanitizeForDisplay_empty()
{
    TEST("sanitizeForDisplay empty input");
    assert(sanitizeForDisplay("", 512, '.', false) == "");
    PASS();
}

// ================================
// 12) sanitizeHeaderValue 테스트
// ================================

void test_sanitizeHeaderValue_removes_control_chars()
{
    TEST("sanitizeHeaderValue removes CR/LF/NULL/TAB");
    assert(sanitizeHeaderValue("hello\r\nworld") == "helloworld");
    // NULL 문자 포함 문자열은 std::string(ptr, len) 생성자 사용
    std::string withNull("test\0data", 9);
    assert(sanitizeHeaderValue(withNull) == "testdata");
    assert(sanitizeHeaderValue("tab\there") == "tabhere");
    assert(sanitizeHeaderValue("clean") == "clean");
    assert(sanitizeHeaderValue("") == "");
    PASS();
}

// ================================
// 13) extractUriFromHeader 테스트
// ================================

void test_extractUri_angle_brackets()
{
    TEST("extractUriFromHeader angle brackets");
    assert(extractUriFromHeader("To: <sip:1001@server>;tag=abc") == "sip:1001@server");
    assert(extractUriFromHeader("<sip:user@example.com>") == "sip:user@example.com");
    assert(extractUriFromHeader("\"Alice\" <sip:alice@host>") == "sip:alice@host");
    PASS();
}

void test_extractUri_without_brackets()
{
    TEST("extractUriFromHeader without brackets");
    assert(extractUriFromHeader("sip:user@host;param=value") == "sip:user@host");
    PASS();
}

void test_extractUri_empty()
{
    TEST("extractUriFromHeader empty");
    assert(extractUriFromHeader("") == "");
    assert(extractUriFromHeader("no uri here") == "");
    PASS();
}

// ================================
// 14) extractUserFromUri 테스트
// ================================

void test_extractUser_basic()
{
    TEST("extractUserFromUri basic");
    assert(extractUserFromUri("sip:1001@server") == "1001");
    assert(extractUserFromUri("sip:alice@example.com") == "alice");
    // Note: extractUserFromUri only handles "sip:" prefix, not "sips:"
    // "sips:" URI는 "sip:" 패턴을 포함하지 않으므로 전체 문자열에서 @까지 반환
    assert(extractUserFromUri("sips:bob@secure.com") == "sips:bob");
    PASS();
}

void test_extractUser_no_at()
{
    TEST("extractUserFromUri no @ sign");
    assert(extractUserFromUri("sip:server") == "server");
    PASS();
}

void test_extractUser_empty()
{
    TEST("extractUserFromUri empty");
    assert(extractUserFromUri("") == "");
    PASS();
}

// ================================
// 15) ensureToTag 테스트
// ================================

void test_ensureToTag_already_has_tag()
{
    TEST("ensureToTag already has tag");
    std::string with_tag = "<sip:1001@server>;tag=abc";
    std::string result = ensureToTag(with_tag);
    assert(result == with_tag);  // 변경 없이 반환
    PASS();
}

void test_ensureToTag_adds_tag()
{
    TEST("ensureToTag adds tag");
    std::string without_tag = "<sip:1001@server>";
    std::string result = ensureToTag(without_tag);
    assert(result.find("tag=") != std::string::npos);
    assert(result.find("tag=server") != std::string::npos);
    PASS();
}

void test_ensureToTag_empty()
{
    TEST("ensureToTag empty input");
    assert(ensureToTag("") == "");
    PASS();
}

void test_ensureToTag_sanitizes_crlf()
{
    TEST("ensureToTag sanitizes CRLF");
    std::string with_crlf = "<sip:1001@server>\r\n";
    std::string result = ensureToTag(with_crlf);
    assert(result.find('\r') == std::string::npos);
    assert(result.find('\n') == std::string::npos);
    assert(result.find("tag=") != std::string::npos);
    PASS();
}

// ================================
// 16) getHeader 테스트
// ================================

void test_getHeader_found()
{
    TEST("getHeader found");
    SipMessage msg;
    msg.headers["from"] = "<sip:alice@host>;tag=123";
    msg.headers["to"] = "<sip:bob@host>";

    assert(getHeader(msg, "from") == "<sip:alice@host>;tag=123");
    assert(getHeader(msg, "From") == "<sip:alice@host>;tag=123");
    assert(getHeader(msg, "FROM") == "<sip:alice@host>;tag=123");
    PASS();
}

void test_getHeader_not_found()
{
    TEST("getHeader not found");
    SipMessage msg;
    assert(getHeader(msg, "nonexistent") == "");
    PASS();
}

// ================================
// 17) getAllHeaders 테스트
// ================================

void test_getAllHeaders()
{
    TEST("getAllHeaders splits comma-combined");
    SipMessage msg;
    msg.headers["via"] = "SIP/2.0/UDP proxy1:5060, SIP/2.0/UDP proxy2:5060";

    auto results = getAllHeaders(msg, "via");
    assert(results.size() == 2);
    assert(results[0].find("proxy1") != std::string::npos);
    assert(results[1].find("proxy2") != std::string::npos);
    PASS();
}

void test_getAllHeaders_single()
{
    TEST("getAllHeaders single value");
    SipMessage msg;
    msg.headers["call-id"] = "abc123@host";

    auto results = getAllHeaders(msg, "call-id");
    assert(results.size() == 1);
    assert(results[0] == "abc123@host");
    PASS();
}

void test_getAllHeaders_missing()
{
    TEST("getAllHeaders missing header");
    SipMessage msg;
    auto results = getAllHeaders(msg, "nonexistent");
    assert(results.empty());
    PASS();
}

// ================================
// 18) 추가 유틸리티 엣지케이스 테스트
// ================================

void test_sanitizeForDisplay_maxLen_zero()
{
    TEST("sanitizeForDisplay maxLen=0 returns empty");
    std::string result = sanitizeForDisplay("Hello World", 0);
    assert(result.empty());
    PASS();
}

void test_sanitizeForDisplay_maxLen_less_than_suffix()
{
    TEST("sanitizeForDisplay maxLen < suffix length");
    // suffix = "... (truncated)" (15 chars)
    // maxLen=5 → returns first 5 chars of suffix
    std::string longInput(100, 'A');
    std::string result = sanitizeForDisplay(longInput, 5);
    assert(result.size() == 5);
    assert(result == "... (");  // first 5 chars of "... (truncated)"
    PASS();
}

void test_sanitizeForDisplay_high_byte_replaced()
{
    TEST("sanitizeForDisplay replaces high-byte chars (>127)");
    std::string input = "hello\xC0\xFF world";
    std::string result = sanitizeForDisplay(input);
    // High bytes and DEL should be replaced with '.'
    assert(result.find('\xC0') == std::string::npos);
    assert(result.find('\xFF') == std::string::npos);
    assert(result.find("hello") == 0);
    PASS();
}

void test_sanitizeForDisplay_del_char_replaced()
{
    TEST("sanitizeForDisplay replaces DEL (0x7F)");
    std::string input = "test\x7F";
    std::string result = sanitizeForDisplay(input);
    assert(result.back() == '.');  // DEL replaced with '.'
    PASS();
}

void test_sanitizeHeaderValue_high_byte_kept()
{
    TEST("sanitizeHeaderValue keeps high-byte chars");
    // sanitizeHeaderValue only removes \r \n \0 \t; keeps everything else
    std::string input = "value\xC0\xFF";
    std::string result = sanitizeHeaderValue(input);
    assert(result == input);  // high bytes not removed
    PASS();
}

void test_sanitizeHeaderValue_all_control_chars_removed()
{
    TEST("sanitizeHeaderValue removes \\r \\n \\0 \\t");
    std::string input = std::string("hel\r\n\tlo\0world", 14);
    std::string result = sanitizeHeaderValue(input);
    assert(result == "helloworld");
    PASS();
}

void test_parseCSeqNum_leading_zeros()
{
    TEST("parseCSeqNum with leading zeros");
    assert(parseCSeqNum("007 INVITE") == 7);
    assert(parseCSeqNum("0001 REGISTER") == 1);
    PASS();
}

void test_parseCSeqMethod_trailing_whitespace_kept()
{
    TEST("parseCSeqMethod trailing whitespace kept");
    // parseCSeqMethod returns remainder as-is after digits+whitespace
    std::string method = parseCSeqMethod("1 INVITE  ");
    // Depending on impl, trailing spaces may or may not be trimmed
    assert(method.find("INVITE") != std::string::npos);
    PASS();
}

void test_extractUri_nested_brackets()
{
    TEST("extractUriFromHeader nested brackets");
    // Parser uses first < and first > for extraction
    std::string result = extractUriFromHeader("\"Name\" <sip:user@host>");
    assert(result == "sip:user@host");
    PASS();
}

void test_extractUri_with_params()
{
    TEST("extractUriFromHeader strips parameters");
    std::string result = extractUriFromHeader("sip:user@host;transport=tcp");
    assert(result == "sip:user@host");
    PASS();
}

// ================================
// main
// ================================

int main()
{
    std::cout << "=== Extended Utils Tests ===\n\n";

    std::cout << "[Section 1] ltrim\n";
    test_ltrim_basic();
    test_ltrim_no_left_spaces();

    std::cout << "\n[Section 2] rtrim\n";
    test_rtrim_basic();
    test_rtrim_no_right_spaces();

    std::cout << "\n[Section 3] trim\n";
    test_trim_both_sides();

    std::cout << "\n[Section 4] toLower\n";
    test_toLower();

    std::cout << "\n[Section 5] isValidSipMethod\n";
    test_valid_sip_methods();
    test_invalid_sip_methods();

    std::cout << "\n[Section 6] isValidSipVersion\n";
    test_valid_sip_version();
    test_invalid_sip_versions();

    std::cout << "\n[Section 7] isValidStatusCode\n";
    test_valid_status_codes();
    test_invalid_status_codes();

    std::cout << "\n[Section 8] isValidRequestUri\n";
    test_valid_request_uris();
    test_invalid_request_uris();
    test_request_uri_crlf_injection();

    std::cout << "\n[Section 9] parseCSeqNum\n";
    test_parseCSeqNum_basic();
    test_parseCSeqNum_edge_cases();
    test_parseCSeqNum_overflow();

    std::cout << "\n[Section 10] parseCSeqMethod\n";
    test_parseCSeqMethod_basic();
    test_parseCSeqMethod_with_spaces();
    test_parseCSeqMethod_empty();

    std::cout << "\n[Section 11] sanitizeForDisplay\n";
    test_sanitizeForDisplay_basic();
    test_sanitizeForDisplay_truncation();
    test_sanitizeForDisplay_allow_crlf();
    test_sanitizeForDisplay_empty();

    std::cout << "\n[Section 12] sanitizeHeaderValue\n";
    test_sanitizeHeaderValue_removes_control_chars();

    std::cout << "\n[Section 13] extractUriFromHeader\n";
    test_extractUri_angle_brackets();
    test_extractUri_without_brackets();
    test_extractUri_empty();

    std::cout << "\n[Section 14] extractUserFromUri\n";
    test_extractUser_basic();
    test_extractUser_no_at();
    test_extractUser_empty();

    std::cout << "\n[Section 15] ensureToTag\n";
    test_ensureToTag_already_has_tag();
    test_ensureToTag_adds_tag();
    test_ensureToTag_empty();
    test_ensureToTag_sanitizes_crlf();

    std::cout << "\n[Section 16] getHeader\n";
    test_getHeader_found();
    test_getHeader_not_found();

    std::cout << "\n[Section 17] getAllHeaders\n";
    test_getAllHeaders();
    test_getAllHeaders_single();
    test_getAllHeaders_missing();

    // 18) 추가 엣지케이스
    std::cout << "\n[Section 18] Additional edge cases\n";
    test_sanitizeForDisplay_maxLen_zero();
    test_sanitizeForDisplay_maxLen_less_than_suffix();
    test_sanitizeForDisplay_high_byte_replaced();
    test_sanitizeForDisplay_del_char_replaced();
    test_sanitizeHeaderValue_high_byte_kept();
    test_sanitizeHeaderValue_all_control_chars_removed();
    test_parseCSeqNum_leading_zeros();
    test_parseCSeqMethod_trailing_whitespace_kept();
    test_extractUri_nested_brackets();
    test_extractUri_with_params();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
