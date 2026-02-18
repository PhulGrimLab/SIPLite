#pragma once

#include <string>

struct SipMessage;      // from SipCore.h

/* SIP 프로토콜 텍스트를 의미 한다
예:
INVITE sip:bob@example.com SIP/2.0
Via: SIP/2.0/UDP alice.example.com;branch=z9hG4bK...
From: "Alice" <sip:alice@example.com>
To: <sip:bob@example.com>
Content-Type: application/sdp
Content-Length: 142

v=0
o=alice 2890844526 2890844526 IN IP4 198.51.100.1
...

위와 같은 SIP 메시지 전체 텍스트를 파싱하여 SipMessage 구조체로 변환하는 함수 선언이다.

*/
// Parse raw SIP text into SipMessage. Returns true on success.
// Implementation lives in src/SipParser.cpp to keep heavy parsing logic out of headers.
bool parseSipMessage(const std::string& raw, SipMessage& out) noexcept;