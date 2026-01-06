#include "SipParser.h"
#include "SipCore.h"

#include <sstream>
#include <charconv>
#include <cctype>
#include <algorithm>

bool parseSipMessage(const std::string& raw, SipMessage& out) noexcept
{
    try
    {
        out = SipMessage{};

        // 입력 크기 검증
        if (raw.empty() || raw.size() > SipConstants::MAX_MESSAGE_SIZE)
        {
            return false;
        }

        // 헤더/바디 분리
        std::size_t headerEnd = raw.find("\r\n\r\n");
        if (headerEnd == std::string::npos)
        {
            return false;
        }

        // 헤더 크기 검증
        if (headerEnd > SipConstants::MAX_HEADER_SIZE)
        {
            return false;
        }

        std::string headerPart = raw.substr(0, headerEnd);
        std::string bodyPart   = raw.substr(headerEnd + 4);

        // 바디 크기 검증
        if (bodyPart.size() > SipConstants::MAX_BODY_SIZE)
        {
            return false;
        }

        // 첫 줄 (Request-Line 또는 Status-Line)
        std::size_t firstLineEnd = headerPart.find("\r\n");
        if (firstLineEnd == std::string::npos)
        {
            return false;
        }

        std::string firstLine = headerPart.substr(0, firstLineEnd);
        firstLine = trim(firstLine);

        if (firstLine.empty())
        {
            return false;
        }

        // Response 인지 Request인지 판별
        if (firstLine.rfind("SIP/2.0", 0) == 0)
        {
            // Response: "SIP/2.0 200 OK"
            std::istringstream iss(firstLine);
            std::string proto;
            iss >> proto >> out.statusCode;
            std::getline(iss, out.reasonPhrase);
            out.reasonPhrase = trim(out.reasonPhrase);
            out.sipVersion   = proto;
            out.type         = SipType::Response;

            // SIP 버전 검증
            if (!isValidSipVersion(out.sipVersion))
            {
                return false;
            }

            // 상태 코드 유효성 검증
            if (!isValidStatusCode(out.statusCode))
            {
                return false;
            }
        }
        else
        {
            // Request: "INVITE sip:1002@server SIP/2.0"
            std::istringstream iss(firstLine);
            iss >> out.method >> out.requestUri >> out.sipVersion;
            if (out.sipVersion.empty()) out.sipVersion = "SIP/2.0";
            out.type = SipType::Request;

            // 메소드 유효성 검증
            if (!isValidSipMethod(out.method))
            {
                return false;
            }

            // SIP 버전 검증
            if (!isValidSipVersion(out.sipVersion))
            {
                return false;
            }

            // Request URI 검증
            if (!isValidRequestUri(out.requestUri))
            {
                return false;
            }
        }

        // 헤더들 파싱
        std::size_t pos = firstLineEnd + 2;
        std::string lastHeaderName;
        std::size_t headerCount = 0;

        while (pos < headerPart.size())
        {
            // 헤더 개수 제한 검사
            if (headerCount >= SipConstants::MAX_HEADERS_COUNT)
            {
                return false;
            }

            std::size_t next = headerPart.find("\r\n", pos);
            std::string line;
            if (next == std::string::npos)
            {
                line = headerPart.substr(pos);
                pos  = headerPart.size();
            }
            else
            {
                line = headerPart.substr(pos, next - pos);
                pos  = next + 2;
            }

            if (line.empty())
            {
                break; // 빈 줄이면 끝
            }

            // 헤더 지속 줄(공백으로 시작) 처리
            if ((line[0] == ' ' || line[0] == '\t') && !lastHeaderName.empty())
            {
                auto& hv = out.headers[lastHeaderName];
                hv += " ";
                hv += trim(line);
                continue;
            }

            std::size_t colon = line.find(':');
            if (colon == std::string::npos)
            {
                continue;
            }

            std::string name  = toLower(trim(line.substr(0, colon)));
            std::string value = trim(line.substr(colon + 1));

            lastHeaderName = name;
            out.headers[name] = value;
            ++headerCount;
        }

        // 바디
        out.body = bodyPart;

        return true;
    }
    catch (const std::exception&)
    {
        // 파싱 중 예외 발생 시 안전하게 실패 처리
        out = SipMessage{};
        return false;
    }
}
