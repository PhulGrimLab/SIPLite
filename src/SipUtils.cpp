#include "SipUtils.h"
#include "SipCore.h" // for SipMessage and SipConstants

#include <cctype>
#include <algorithm>
#include <charconv>
#include <array>
#include <cstdint>
#include <cstring>

namespace
{
    inline std::uint32_t leftRotate(std::uint32_t value, std::uint32_t shift)
    {
        return (value << shift) | (value >> (32U - shift));
    }
}

// 왼쪽 공백 제거
std::string ltrim(const std::string& s)
{
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
    {
        ++i;
    }

    return s.substr(i);
}

// 오른쪽 공백 제거
std::string rtrim(const std::string& s)
{
    if (s.empty())
    {
        return s;
    }

    std::size_t i = s.size();
    while (i > 0 && std::isspace(static_cast<unsigned char>(s[i - 1])))
    {
        --i;
    }

    return s.substr(0, i);
}

// 양쪽 공백 제거
std::string trim(const std::string& s)
{
    return rtrim(ltrim(s));
}

// 문자열을 소문자로 변환
std::string toLower(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
    {
        out.push_back(static_cast<char>(std::tolower(c)));
    }

    return out;
}

// SIP 메시지에서 특정 헤더 값 가져오기 (대소문자 구분 없이)
// 예: getHeader(msg, "From") -> "Alice <sip:user@example.com>"
// SIP 메시지의 헤더는 대소문자 구분 없이 검색할 수 있도록, 내부적으로 모든 헤더 이름을 소문자로 저장한다고 가정합니다.
std::string getHeader(const SipMessage& msg, const std::string& name)
{
    auto it = msg.headers.find(toLower(name));
    if (it == msg.headers.end())
    {
        return std::string{};
    }

    return it->second;
}

// SIP 메시지에서 특정 이름의 모든 헤더 값 가져오기 (예: Via 다중 헤더)
// 헤더가 콤마로 결합되어 있으므로 (RFC 3261 Section 7.3.1) 분리하여 반환
std::vector<std::string> getAllHeaders(const SipMessage& msg, const std::string& name)
{
    std::vector<std::string> results;
    std::string key = toLower(name);
    auto it = msg.headers.find(key);
    if (it == msg.headers.end())
        return results;

    // 콤마로 결합된 헤더 값을 개별 값으로 분리
    const std::string& combined = it->second;
    std::size_t start = 0;
    while (start < combined.size())
    {
        std::size_t comma = combined.find(',', start);
        std::string val;
        if (comma == std::string::npos)
        {
            val = trim(combined.substr(start));
            start = combined.size();
        }
        else
        {
            val = trim(combined.substr(start, comma - start));
            start = comma + 1;
        }
        if (!val.empty())
        {
            results.push_back(std::move(val));
        }
    }
    return results;
}

// SIP 메시지의 헤더 값에서 CR, LF, NULL 문자를 제거하여 정화된 문자열 반환
// SIP 메시지의 헤더 값은 로그에 출력할 때 문제가 될 수 있는 제어 문자를 포함할 수 있습니다.
// 이 함수는 헤더 값에서 CR, LF, NULL 문자를 제거하여 로그에 출력할 때 안전한 문자열로 변환하는 역할을 합니다.
// 예: "Alice\r\n" -> "Alice", "Bob\0Smith" -> "BobSmith"
// SIP 메시지 데이터에서 출력 가능한 ASCII 문자와 일부 공백 문자를 유지하면서, 로그에 출력할 때 문제가 될 수 있는 비출력 문자를 정화하는 함수입니다.    
std::string sanitizeHeaderValue(const std::string& value)
{
    std::string result;
    result.reserve(value.size());

    for (char c : value)
    {
        if (c != '\r' && c != '\n' && c != '\0' && c != '\t')
        {
            result += c;
        }
    }

    return result;
}

// 로그에 출력할 SIP 메시지 데이터 정화
// SIP 메시지는 구조적으로 여러 줄로 구성되며, CR, LF, TAB 등의 제어 문자를 포함할 수 있습니다.
// 이 함수는 SIP 메시지의 구조를 유지하면서, 로그에 출력할 때 문제가 될 수 있는 비출력 문자를 정화하는 역할을 합니다.
// SIP 메시지의 각 줄은 CRLF로 구분되므로, CR과 LF는 유지하면서 다른 비출력 문자는 '.'으로 대체합니다. 
// "INVITE sip:user@example.com SIP/2.0\r\n" -> "INVITE sip:user@example.com SIP/2.0"
// "v=0\r\no=alice 2890844526 2890844526 IN IP4
std::string extractUriFromHeader(const std::string& headerValue)
{
    std::string v = headerValue;
    auto lt = v.find('<');
    auto gt = v.find('>');

    if (lt != std::string::npos && gt != std::string::npos && gt > lt + 1)
    {
        return trim(v.substr(lt + 1, gt - lt - 1));
    }

    auto semi = v.find(';');
    if (semi != std::string::npos)
    {
        v = v.substr(0, semi);
    }

    v = trim(v);

    auto sipPos = v.find("sip:");
    if (sipPos != std::string::npos)
    {
        return trim(v.substr(sipPos));
    }

    return std::string{};
}

// SIP URI에서 사용자 부분 추출
// 예: "sip:user@example.com" -> "user"
std::string extractUserFromUri(const std::string& uri)
{
    std::string u = uri;
    auto sipPos = u.find("sip:");
    std::size_t start = (sipPos == std::string::npos) ? 0 : sipPos + 4;
    auto atPos = u.find('@', start);

    if (atPos == std::string::npos)
    {
        return trim(u.substr(start));
    }

    return trim(u.substr(start, atPos - start));
}

std::string extractAorKeyFromUri(const std::string& uri)
{
    std::string u = trim(uri);
    if (u.empty())
    {
        return {};
    }

    const std::string lower = toLower(u);
    std::size_t start = 0;
    if (lower.rfind("sip:", 0) == 0)
    {
        start = 4;
    }
    else if (lower.rfind("sips:", 0) == 0)
    {
        start = 5;
    }

    std::size_t hostStart = start;
    std::string user;
    const std::size_t atPos = u.find('@', start);
    if (atPos != std::string::npos)
    {
        user = toLower(trim(u.substr(start, atPos - start)));
        hostStart = atPos + 1;
    }

    std::size_t hostEnd = u.find_first_of(";?>", hostStart);
    if (hostEnd == std::string::npos)
    {
        hostEnd = u.size();
    }

    const std::size_t colonPos = u.find(':', hostStart);
    if (colonPos != std::string::npos && colonPos < hostEnd)
    {
        const std::string afterColon = u.substr(colonPos + 1, hostEnd - (colonPos + 1));
        bool portOnly = !afterColon.empty();
        for (char c : afterColon)
        {
            if (!std::isdigit(static_cast<unsigned char>(c)))
            {
                portOnly = false;
                break;
            }
        }
        if (portOnly)
        {
            hostEnd = colonPos;
        }
    }

    const std::string host = toLower(trim(u.substr(hostStart, hostEnd - hostStart)));
    if (host.empty())
    {
        return {};
    }

    if (user.empty())
    {
        return host;
    }

    return user + "@" + host;
}

// SIP 메서드 유효성 검사
// SIP 메서드는 RFC3261에서 정의된 메서드 집합에 속해야 합니다.
// 예: "INVITE" -> valid, "FOO" -> invalid, "BYE" -> valid
// SIP 메서드는 대문자로만 구성되어야 합니다.
// SIP 메서드는 7비트 ASCII 대문자로만 구성되어야 하며, RFC3261에서 정의된 메서드 집합에 속해야 합니다.
bool isValidSipMethod(const std::string& method)
{
    static const std::unordered_set<std::string> validMethods = {
        "INVITE", "ACK", "BYE", "CANCEL", "REGISTER",
        "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY",
        "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"
    };
    return validMethods.find(method) != validMethods.end();
}

// SIP 버전은 "SIP/2.0"만 유효
bool isValidSipVersion(const std::string& version)
{
    return version == "SIP/2.0";
}

// 상태 코드는 100-699 범위 내의 정수여야 합니다.
// 예: 200 -> valid, 99 -> invalid, 700 -> invalid, 180 -> valid
// SIP 상태 코드는 3자리 숫자여야 하며, 첫 자리는 1-6 사이여야 합니다.
// RFC3261에서는 100-699 범위의 상태 코드만 정의되어 있습니다.
bool isValidStatusCode(int code)
{
    return code >= 100 && code <= 699;
}

// Request URI 기본 검증
// SIP URI는 "sip:" 또는 "sips:"로 시작해야 하며, 256자 이하이어야 합니다. 
// 또한, CR, LF, NULL 문자를 포함해서는 안 됩니다.
// 예: "sip:user@example.com"  -> valid, 
//"http://example.com" -> invalid, "sip:user@example.com\r" -> invalid   
bool isValidRequestUri(const std::string& uri)
{
    if (uri.empty() || uri.size() > 256)
    {
        return false;
    }

    if (uri.substr(0, 4) != "sip:" && uri.substr(0, 5) != "sips:")
    {
        return false;
    }

    for (char c : uri)
    {
        if (c == '\r' || c == '\n' || c == '\0')
        {
            return false;
        }
    }

    return true;
}

// CSeq 헤더에서 번호 추출 (오버플로우 시 -1 반환)
int parseCSeqNum(const std::string& cseq)
{
    long long num = 0;
    size_t i = 0;
    bool found = false;
    while (i < cseq.size() && std::isspace(static_cast<unsigned char>(cseq[i]))) ++i;
    while (i < cseq.size() && std::isdigit(static_cast<unsigned char>(cseq[i])))
    {
        num = num * 10 + (cseq[i] - '0');
        if (num > static_cast<long long>(std::numeric_limits<int>::max()))
        {
            return -1; // overflow
        }
        found = true;
        ++i;
    }
    if (!found) return -1;
    return static_cast<int>(num);
}

// CSeq 헤더에서 메서드 추출 (선행 공백 처리 포함)
std::string parseCSeqMethod(const std::string& cseq)
{
    size_t pos = 0;
    // 선행 공백 건너뛰기
    while (pos < cseq.size() && std::isspace(static_cast<unsigned char>(cseq[pos]))) ++pos;
    // 숫자 건너뛰기
    while (pos < cseq.size() && std::isdigit(static_cast<unsigned char>(cseq[pos]))) ++pos;
    // 숫자와 메서드 사이 공백 건너뛰기
    while (pos < cseq.size() && std::isspace(static_cast<unsigned char>(cseq[pos]))) ++pos;
    return cseq.substr(pos);
}

// 로그/출력용 문자열 정화
std::string sanitizeForDisplay(const std::string& input,
                                std::size_t maxLen,
                                char replacement,
                                bool allowCrLfTab)
{
    const std::string suffix = "... (truncated)";
    const std::size_t suffixLen = suffix.size();

    std::string result;

    std::size_t contentMax = maxLen;
    if (input.size() > maxLen)
    {
        result.reserve(maxLen);
        if (maxLen > suffixLen)
        {
            contentMax = maxLen - suffixLen;
        }
        else
        {
            contentMax = 0;
        }
    }
    else
    {
        result.reserve(input.size());
        contentMax = input.size();
    }

    for (std::size_t i = 0; i < input.size() && result.size() < contentMax; ++i)
    {
        unsigned char uc = static_cast<unsigned char>(input[i]);
        if (uc >= 32 && uc < 127)
        {
            result += static_cast<char>(uc);
        }
        else if (allowCrLfTab && (uc == '\r' || uc == '\n' || uc == '\t'))
        {
            result += static_cast<char>(uc);
        }
        else
        {
            result += replacement;
        }
    }

    if (input.size() > maxLen)
    {
        if (maxLen > suffixLen)
        {
            result += suffix;
        }
        else if (maxLen > 0)
        {
            result = suffix.substr(0, maxLen);
        }
    }

    return result;
}

// To 헤더에 tag 없으면 tag=server 추가
// SIP 메시지에 포함된 To 헤더에서 tag 파라미터가 없으면, 서버에서 자체적으로 tag=server를 추가하여 반환하는 함수입니다.
// 예: "To: <sip:user@example.com>" -> "To: <sip:user@example.com>;tag=server"
std::string ensureToTag(const std::string& to)
{
    std::string sanitized = sanitizeHeaderValue(to);

    if (sanitized.find("tag=") != std::string::npos)
    {
        return sanitized;
    }

    if (sanitized.empty())
    {
        return sanitized;
    }

    return sanitized + ";tag=server";
}

std::string md5Hex(const std::string& input)
{
    static constexpr std::array<std::uint32_t, 64> k = {
        0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU,
        0xf57c0fafU, 0x4787c62aU, 0xa8304613U, 0xfd469501U,
        0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
        0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U,
        0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
        0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
        0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU,
        0xa9e3e905U, 0xfcefa3f8U, 0x676f02d9U, 0x8d2a4c8aU,
        0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
        0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
        0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U,
        0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
        0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U,
        0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU, 0x85845dd1U,
        0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
        0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U
    };
    static constexpr std::array<std::uint32_t, 64> s = {
        7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U, 7U, 12U, 17U, 22U,
        5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U, 5U, 9U, 14U, 20U,
        4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U, 4U, 11U, 16U, 23U,
        6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U, 6U, 10U, 15U, 21U
    };
    static constexpr char hex[] = "0123456789abcdef";

    std::uint64_t bitLength = static_cast<std::uint64_t>(input.size()) * 8U;
    std::size_t paddedSize = input.size() + 1U;
    while ((paddedSize % 64U) != 56U)
    {
        ++paddedSize;
    }
    paddedSize += 8U;

    std::string padded(paddedSize, '\0');
    std::memcpy(padded.data(), input.data(), input.size());
    padded[input.size()] = static_cast<char>(0x80);
    for (std::size_t i = 0; i < 8U; ++i)
    {
        padded[paddedSize - 8U + i] = static_cast<char>((bitLength >> (8U * i)) & 0xffU);
    }

    std::uint32_t a0 = 0x67452301U;
    std::uint32_t b0 = 0xefcdab89U;
    std::uint32_t c0 = 0x98badcfeU;
    std::uint32_t d0 = 0x10325476U;

    for (std::size_t offset = 0; offset < padded.size(); offset += 64U)
    {
        std::uint32_t m[16] = {};
        for (std::size_t i = 0; i < 16U; ++i)
        {
            std::size_t idx = offset + (i * 4U);
            m[i] = static_cast<std::uint32_t>(static_cast<unsigned char>(padded[idx])) |
                   (static_cast<std::uint32_t>(static_cast<unsigned char>(padded[idx + 1U])) << 8U) |
                   (static_cast<std::uint32_t>(static_cast<unsigned char>(padded[idx + 2U])) << 16U) |
                   (static_cast<std::uint32_t>(static_cast<unsigned char>(padded[idx + 3U])) << 24U);
        }

        std::uint32_t a = a0;
        std::uint32_t b = b0;
        std::uint32_t c = c0;
        std::uint32_t d = d0;

        for (std::uint32_t i = 0; i < 64U; ++i)
        {
            std::uint32_t f = 0;
            std::uint32_t g = 0;

            if (i < 16U)
            {
                f = (b & c) | (~b & d);
                g = i;
            }
            else if (i < 32U)
            {
                f = (d & b) | (~d & c);
                g = (5U * i + 1U) % 16U;
            }
            else if (i < 48U)
            {
                f = b ^ c ^ d;
                g = (3U * i + 5U) % 16U;
            }
            else
            {
                f = c ^ (b | ~d);
                g = (7U * i) % 16U;
            }

            std::uint32_t temp = d;
            d = c;
            c = b;
            b = b + leftRotate(a + f + k[i] + m[g], s[i]);
            a = temp;
        }

        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    std::uint32_t digest[4] = {a0, b0, c0, d0};
    std::string out;
    out.reserve(32);
    for (std::uint32_t word : digest)
    {
        for (std::size_t i = 0; i < 4U; ++i)
        {
            unsigned char byte = static_cast<unsigned char>((word >> (8U * i)) & 0xffU);
            out.push_back(hex[byte >> 4U]);
            out.push_back(hex[byte & 0x0fU]);
        }
    }

    return out;
}
