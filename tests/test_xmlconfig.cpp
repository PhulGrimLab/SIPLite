#include "XmlConfigLoader.h"
#include "SipCore.h"
#include <cassert>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

// 임시 파일 생성 헬퍼
static const std::string TEST_DIR = "/tmp/siplite_test_xml";

static void ensureTestDir()
{
    std::filesystem::create_directories(TEST_DIR);
}

static void writeFile(const std::string& filename, const std::string& content)
{
    std::ofstream f(filename, std::ios::binary);
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
    f.close();
}

static void cleanupFile(const std::string& filename)
{
    std::error_code ec;
    std::filesystem::remove(filename, ec);
}

// ================================
// 1) 정상적인 XML 파싱
// ================================

void test_load_valid_xml()
{
    TEST("Load valid XML with terminals");
    ensureTestDir();
    std::string path = TEST_DIR + "/valid.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>5060</port>\n"
        "    <expires>3600</expires>\n"
        "    <description>Test Phone 1</description>\n"
        "  </terminal>\n"
        "  <terminal>\n"
        "    <aor>sip:1002@server</aor>\n"
        "    <contact>sip:1002@10.0.0.2:5060</contact>\n"
        "    <ip>10.0.0.2</ip>\n"
        "    <port>5060</port>\n"
        "    <expires>7200</expires>\n"
        "    <description>Test Phone 2</description>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 2);
    assert(terminals[0].aor == "sip:1001@server");
    assert(terminals[0].ip == "10.0.0.1");
    assert(terminals[0].port == 5060);
    assert(terminals[0].expiresSec == 3600);
    assert(terminals[0].description == "Test Phone 1");
    assert(terminals[1].aor == "sip:1002@server");
    assert(terminals[1].ip == "10.0.0.2");

    cleanupFile(path);
    PASS();
}

void test_load_xml_default_port()
{
    TEST("Load XML with default port");
    ensureTestDir();
    std::string path = TEST_DIR + "/defaultport.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].port == 5060);  // 기본 포트
    assert(terminals[0].expiresSec == 3600);  // 기본 만료 시간

    cleanupFile(path);
    PASS();
}

// ================================
// 2) 빈 파일 / 존재하지 않는 파일
// ================================

void test_load_nonexistent_file()
{
    TEST("Load nonexistent file returns empty");
    auto terminals = XmlConfigLoader::loadTerminals(TEST_DIR + "/nonexistent.xml");
    assert(terminals.empty());
    PASS();
}

void test_load_empty_file()
{
    TEST("Load empty file returns empty");
    ensureTestDir();
    std::string path = TEST_DIR + "/empty.xml";
    writeFile(path, "");

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

// ================================
// 3) XXE 방지 테스트
// ================================

void test_xxe_entity_rejected()
{
    TEST("XXE: <!ENTITY rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/xxe.xml";
    std::string xml =
        "<!DOCTYPE foo [\n"
        "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
        "]>\n"
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());  // XXE 감지 → 거부

    cleanupFile(path);
    PASS();
}

void test_xxe_doctype_rejected()
{
    TEST("XXE: <!DOCTYPE rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/doctype.xml";
    std::string xml =
        "<!DOCTYPE foo SYSTEM \"http://evil.com/dtd\">\n"
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

void test_xxe_file_protocol_rejected()
{
    TEST("XXE: file:// protocol rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/fileproto.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>file:///etc/passwd</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

void test_xxe_http_protocol_rejected()
{
    TEST("XXE: http:// protocol rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/httpproto.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>http://evil.com/data</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

// ================================
// 4) 경로 보안 테스트
// ================================

void test_path_traversal_rejected()
{
    TEST("Path traversal rejected");
    auto terminals = XmlConfigLoader::loadTerminals("../../../etc/passwd.xml");
    assert(terminals.empty());
    PASS();
}

void test_non_xml_extension_rejected()
{
    TEST("Non-XML extension rejected");
    auto terminals = XmlConfigLoader::loadTerminals("/tmp/config.txt");
    assert(terminals.empty());
    PASS();
}

void test_empty_path_rejected()
{
    TEST("Empty path rejected");
    auto terminals = XmlConfigLoader::loadTerminals("");
    assert(terminals.empty());
    PASS();
}

// ================================
// 5) 잘못된 IP 주소
// ================================

void test_invalid_ip_skipped()
{
    TEST("Invalid IP address skipped");
    ensureTestDir();
    std::string path = TEST_DIR + "/badip.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@999.999.999.999:5060</contact>\n"
        "    <ip>999.999.999.999</ip>\n"
        "  </terminal>\n"
        "  <terminal>\n"
        "    <aor>sip:1002@server</aor>\n"
        "    <contact>sip:1002@10.0.0.2:5060</contact>\n"
        "    <ip>10.0.0.2</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);  // 잘못된 IP는 건너뜀
    assert(terminals[0].ip == "10.0.0.2");

    cleanupFile(path);
    PASS();
}

void test_leading_zero_ip_rejected()
{
    TEST("Leading zero in IP rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/leadingzero.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@010.0.0.1:5060</contact>\n"
        "    <ip>010.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());  // 선행 0 있는 IP 거부

    cleanupFile(path);
    PASS();
}

// ================================
// 6) 잘못된 AOR
// ================================

void test_invalid_aor_skipped()
{
    TEST("Invalid AOR (no sip: prefix) skipped");
    ensureTestDir();
    std::string path = TEST_DIR + "/badaor.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>http://1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

// ================================
// 7) 잘못된 포트
// ================================

void test_invalid_port_uses_default()
{
    TEST("Invalid port uses default 5060");
    ensureTestDir();
    std::string path = TEST_DIR + "/badport.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>notanumber</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].port == 5060);

    cleanupFile(path);
    PASS();
}

void test_zero_port_rejected()
{
    TEST("Zero port uses default");
    ensureTestDir();
    std::string path = TEST_DIR + "/zeroport.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>0</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].port == 5060);  // 0은 무효 → 기본값

    cleanupFile(path);
    PASS();
}

// ================================
// 8) registerTerminals (SipCore 등록)
// ================================

void test_registerTerminals_to_sipcore()
{
    TEST("registerTerminals to SipCore");
    ensureTestDir();
    std::string path = TEST_DIR + "/register.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>5060</port>\n"
        "  </terminal>\n"
        "  <terminal>\n"
        "    <aor>sip:1002@server</aor>\n"
        "    <contact>sip:1002@10.0.0.2:5060</contact>\n"
        "    <ip>10.0.0.2</ip>\n"
        "    <port>5060</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 2);

    SipCore core;
    std::size_t registered = XmlConfigLoader::registerTerminals(core, terminals);
    assert(registered == 2);
    assert(core.registrationCount() == 2);

    auto reg1 = core.findRegistrationSafe("sip:1001@server");
    assert(reg1.has_value());
    assert(reg1->ip == "10.0.0.1");

    auto reg2 = core.findRegistrationSafe("sip:1002@server");
    assert(reg2.has_value());
    assert(reg2->ip == "10.0.0.2");

    cleanupFile(path);
    PASS();
}

// ================================
// 9) XML 엔티티 디코딩
// ================================

void test_xml_entity_decoding()
{
    TEST("XML entity decoding in values");
    ensureTestDir();
    std::string path = TEST_DIR + "/entities.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <description>Phone &amp; Fax</description>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].description == "Phone & Fax");

    cleanupFile(path);
    PASS();
}

// ================================
// 10) validateFilePath 단독 테스트
// ================================

void test_validateFilePath()
{
    TEST("validateFilePath various paths");
    // 유효한 경로
    assert(XmlConfigLoader::validateFilePath("/tmp/config.xml"));
    assert(XmlConfigLoader::validateFilePath("config.xml"));

    // 무효한 경로
    assert(!XmlConfigLoader::validateFilePath(""));       // 빈 경로
    assert(!XmlConfigLoader::validateFilePath("test.txt")); // 잘못된 확장자
    assert(!XmlConfigLoader::validateFilePath("../../../etc/passwd.xml")); // 경로 탈출
    assert(!XmlConfigLoader::validateFilePath("/etc/config.xml")); // /etc/ 접근
    PASS();
}

// ================================
// 11) validateXmlContent 단독 테스트
// ================================

void test_validateXmlContent()
{
    TEST("validateXmlContent detects dangerous patterns");
    // 정상 XML
    assert(XmlConfigLoader::validateXmlContent("<terminals><terminal></terminal></terminals>"));

    // 위험 패턴
    assert(!XmlConfigLoader::validateXmlContent("<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"));
    assert(!XmlConfigLoader::validateXmlContent("<!DOCTYPE foo>"));
    assert(!XmlConfigLoader::validateXmlContent("SYSTEM \"http://evil.com\""));
    assert(!XmlConfigLoader::validateXmlContent("file:///etc/passwd"));
    assert(!XmlConfigLoader::validateXmlContent("http://evil.com"));
    assert(!XmlConfigLoader::validateXmlContent("https://evil.com"));
    assert(!XmlConfigLoader::validateXmlContent("ftp://evil.com"));
    PASS();
}

// ================================
// 12) 추가 XmlConfig 엣지케이스
// ================================

void test_file_exceeds_max_size()
{
    TEST("File exceeding MAX_FILE_SIZE rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/huge.xml";
    // MAX_FILE_SIZE = 1MB, 생성: 1MB + 100bytes
    std::string content(1 * 1024 * 1024 + 100, 'A');
    writeFile(path, content);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

void test_port_65535_valid()
{
    TEST("Port 65535 is valid");
    ensureTestDir();
    std::string path = TEST_DIR + "/port65535.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:65535</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>65535</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].port == 65535);

    cleanupFile(path);
    PASS();
}

void test_port_65536_rejected()
{
    TEST("Port 65536 rejected (uses default 5060)");
    ensureTestDir();
    std::string path = TEST_DIR + "/port65536.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>65536</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    // 포트 65536은 유효하지 않으므로 기본값 5060 사용 또는 스킵
    if (!terminals.empty()) {
        assert(terminals[0].port == 5060);
    }

    cleanupFile(path);
    PASS();
}

void test_sips_aor_valid()
{
    TEST("sips: AOR is valid");
    ensureTestDir();
    std::string path = TEST_DIR + "/sips_aor.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sips:1001@server</aor>\n"
        "    <contact>sips:1001@10.0.0.1:5061</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>5061</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].aor == "sips:1001@server");

    cleanupFile(path);
    PASS();
}

void test_contact_crlf_injection_rejected()
{
    TEST("Contact with CRLF injection rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/crlf_contact.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060&#13;&#10;Injected: header</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <port>5060</port>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    // Contact에 CR/LF가 있으면 isValidContact가 거부
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

void test_numeric_xml_entity_decoding()
{
    TEST("Numeric XML entity &#60; decoded to <");
    ensureTestDir();
    std::string path = TEST_DIR + "/numeric_entity.xml";
    std::string xml =
        "<terminals>\n"
        "  <terminal>\n"
        "    <aor>sip:1001@server</aor>\n"
        "    <contact>sip:1001@10.0.0.1:5060</contact>\n"
        "    <ip>10.0.0.1</ip>\n"
        "    <description>Test &#60;phone&#62;</description>\n"
        "  </terminal>\n"
        "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() == 1);
    assert(terminals[0].description == "Test <phone>");

    cleanupFile(path);
    PASS();
}

void test_tag_depth_exceeded()
{
    TEST("Tag depth > MAX_TAG_DEPTH rejected");
    ensureTestDir();
    std::string path = TEST_DIR + "/deep_tags.xml";
    // MAX_TAG_DEPTH = 5, 생성: 깊이 7
    std::string xml =
        "<a><b><c><d><e><f><g>deep</g></f></e></d></c></b></a>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.empty());

    cleanupFile(path);
    PASS();
}

void test_max_terminals_limit()
{
    TEST("MAX_TERMINALS (1000) limit enforced");
    ensureTestDir();
    std::string path = TEST_DIR + "/many_terminals.xml";
    std::string xml = "<terminals>\n";
    // 1001개의 터미널 생성
    for (int i = 0; i < 1001; ++i) {
        xml += "  <terminal>\n";
        xml += "    <aor>sip:" + std::to_string(i) + "@server</aor>\n";
        xml += "    <contact>sip:" + std::to_string(i) + "@10.0.0.1:5060</contact>\n";
        xml += "    <ip>10.0.0.1</ip>\n";
        xml += "    <port>5060</port>\n";
        xml += "  </terminal>\n";
    }
    xml += "</terminals>\n";
    writeFile(path, xml);

    auto terminals = XmlConfigLoader::loadTerminals(path);
    assert(terminals.size() <= 1000);

    cleanupFile(path);
    PASS();
}

// ================================
// Cleanup
// ================================

void cleanup_test_dir()
{
    std::error_code ec;
    std::filesystem::remove_all(TEST_DIR, ec);
}

// ================================
// main
// ================================

int main()
{
    std::cout << "=== XmlConfigLoader Tests ===\n\n";

    std::cout << "[Section 1] Valid XML loading\n";
    test_load_valid_xml();
    test_load_xml_default_port();

    std::cout << "\n[Section 2] Missing/empty files\n";
    test_load_nonexistent_file();
    test_load_empty_file();

    std::cout << "\n[Section 3] XXE prevention\n";
    test_xxe_entity_rejected();
    test_xxe_doctype_rejected();
    test_xxe_file_protocol_rejected();
    test_xxe_http_protocol_rejected();

    std::cout << "\n[Section 4] Path security\n";
    test_path_traversal_rejected();
    test_non_xml_extension_rejected();
    test_empty_path_rejected();

    std::cout << "\n[Section 5] Invalid IP address\n";
    test_invalid_ip_skipped();
    test_leading_zero_ip_rejected();

    std::cout << "\n[Section 6] Invalid AOR\n";
    test_invalid_aor_skipped();

    std::cout << "\n[Section 7] Invalid port\n";
    test_invalid_port_uses_default();
    test_zero_port_rejected();

    std::cout << "\n[Section 8] registerTerminals\n";
    test_registerTerminals_to_sipcore();

    std::cout << "\n[Section 9] XML entity decoding\n";
    test_xml_entity_decoding();

    std::cout << "\n[Section 10] validateFilePath\n";
    test_validateFilePath();

    std::cout << "\n[Section 11] validateXmlContent\n";
    test_validateXmlContent();

    std::cout << "\n[Section 12] Additional edge cases\n";
    test_file_exceeds_max_size();
    test_port_65535_valid();
    test_port_65536_rejected();
    test_sips_aor_valid();
    test_contact_crlf_injection_rejected();
    test_numeric_xml_entity_decoding();
    test_tag_depth_exceeded();
    test_max_terminals_limit();

    cleanup_test_dir();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
