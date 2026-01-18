#pragma once

#include <string>

struct SipMessage;  // from SipCore.h

// Parse raw SIP text into SipMessage. Returns true on success.
// Implementation lives in src/SipParser.cpp to keep heavy parsing logic out of headers.
bool parseSipMessage(const std::string& raw, SipMessage& out) noexcept;
