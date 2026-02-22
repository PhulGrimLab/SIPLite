#pragma once

#include <string>
#include <vector>
#include <limits>

// String utilities used across SIP core and parser
std::string ltrim(const std::string& s);
std::string rtrim(const std::string& s);
std::string trim(const std::string& s);
std::string toLower(const std::string& s);

// Header sanitization and extraction
std::string getHeader(const struct SipMessage& msg, const std::string& name);
std::vector<std::string> getAllHeaders(const struct SipMessage& msg, const std::string& name);
std::string sanitizeHeaderValue(const std::string& value);
std::string extractUriFromHeader(const std::string& headerValue);
std::string extractUserFromUri(const std::string& uri);

// Validation helpers
bool isValidSipMethod(const std::string& method);
bool isValidSipVersion(const std::string& version);
bool isValidStatusCode(int code);
bool isValidRequestUri(const std::string& uri);

// CSeq 헤더에서 번호 추출 (예: "1 INVITE" → 1, 오버플로우 시 -1 반환)
int parseCSeqNum(const std::string& cseqValue);

// CSeq 헤더에서 메서드 추출 (예: "1 INVITE" → "INVITE")
std::string parseCSeqMethod(const std::string& cseqValue);

// 로그/출력용 문자열 정화 (비출력 문자 대체, 길이 제한)
std::string sanitizeForDisplay(const std::string& input,
                                std::size_t maxLen = 512,
                                char replacement = '.',
                                bool allowCrLfTab = true);

// Helper to ensure To header has tag
std::string ensureToTag(const std::string& to);