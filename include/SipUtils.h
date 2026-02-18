#pragma once

#include <string>

// String utilities used across SIP core and parser
std::string ltrim(const std::string& s);
std::string rtrim(const std::string& s);
std::string trim(const std::string& s);
std::string toLower(const std::string& s);

// Header sanitization and extraction
std::string getHeader(const struct SipMessage& msg, const std::string& name);
std::string sanitizeHeaderValue(const std::string& value);
std::string extractUriFromHeader(const std::string& headerValue);
std::string extractUserFromUri(const std::string& uri);

// Validation helpers
bool isValidSipMethod(const std::string& method);
bool isValidSipVersion(const std::string& version);
bool isValidStatusCode(int code);
bool isValidRequestUri(const std::string& uri);

// Helper to ensure To header has tag
std::string ensureToTag(const std::string& to);