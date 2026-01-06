#include "SipUtils.h"
#include "SipCore.h" // for SipMessage and SipConstants

#include <cctype>
#include <algorithm>
#include <charconv>

std::string ltrim(const std::string& s)
{
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
    {
        ++i;
    }

    return s.substr(i);
}

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

std::string trim(const std::string& s)
{
    return rtrim(ltrim(s));
}

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

std::string getHeader(const SipMessage& msg, const std::string& name)
{
    auto it = msg.headers.find(toLower(name));
    if (it == msg.headers.end())
    {
        return std::string{};
    }

    return it->second;
}

std::string sanitizeHeaderValue(const std::string& value)
{
    std::string result;
    result.reserve(value.size());

    for (char c : value)
    {
        if (c != '\r' && c != '\n' && c != '\0')
        {
            result += c;
        }
    }

    return result;
}

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

bool isValidSipMethod(const std::string& method)
{
    static const std::unordered_set<std::string> validMethods = {
        "INVITE", "ACK", "BYE", "CANCEL", "REGISTER",
        "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY",
        "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"
    };
    return validMethods.find(method) != validMethods.end();
}

bool isValidSipVersion(const std::string& version)
{
    return version == "SIP/2.0";
}

bool isValidStatusCode(int code)
{
    return code >= 100 && code <= 699;
}

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

std::string ensureToTag(const std::string& to)
{
    std::string sanitized = sanitizeHeaderValue(to);

    if (sanitized.find("tag=") != std::string::npos)
    {
        return sanitized;
    }

    if (!sanitized.empty() && sanitized.back() == '>')
    {
        return sanitized + ";tag=server";
    }

    return sanitized + ";tag=server";
}
