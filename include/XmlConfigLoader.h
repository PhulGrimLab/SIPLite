#pragma once

#include "SipCore.h"
#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <charconv>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <optional>

// ================================
// 단말 설정 정보
// ================================

struct TerminalConfig
{
    std::string aor;
    std::string contact;
    std::string ip;
    uint16_t port = 5060;
    int expiresSec = 3600;
    std::string description;
};

// ================================
// XML 설정 로더 (보안 강화 버전)
// ================================

class XmlConfigLoader
{
public:
    // 파일 크기 제한 (1MB로 축소)
    static constexpr std::uintmax_t MAX_FILE_SIZE = 1 * 1024 * 1024;
    // 최대 단말 수 제한
    static constexpr std::size_t MAX_TERMINALS = 1000;
    // 최대 문자열 길이
    static constexpr std::size_t MAX_STRING_LENGTH = 128;
    // 최대 태그 깊이
    static constexpr std::size_t MAX_TAG_DEPTH = 5;

    // XML 파일에서 단말 정보 로드
    static std::vector<TerminalConfig> loadTerminals(const std::string& filePath)
    {
        std::vector<TerminalConfig> terminals;
        terminals.reserve(64);
        
        // 경로 보안 검증
        if (!validateFilePath(filePath))
        {
            std::cerr << "[XmlConfigLoader] 보안: 허용되지 않은 파일 경로\n";
            return terminals;
        }
        
        // 파일 존재 여부 확인
        std::error_code ec;
        if (!std::filesystem::exists(filePath, ec) || ec)
        {
            std::cerr << "[XmlConfigLoader] 파일이 존재하지 않습니다: " << sanitizeForLog(filePath) << "\n";
            return terminals;
        }
        
        // 심볼릭 링크 체크
        if (std::filesystem::is_symlink(filePath, ec))
        {
            std::cerr << "[XmlConfigLoader] 보안: 심볼릭 링크 비허용\n";
            return terminals;
        }
        
        // 파일 크기 검증
        auto fileSize = std::filesystem::file_size(filePath, ec);
        if (ec || fileSize > MAX_FILE_SIZE || fileSize == 0)
        {
            std::cerr << "[XmlConfigLoader] 파일 크기 오류 또는 제한 초과\n";
            return terminals;
        }
        
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open())
        {
            std::cerr << "[XmlConfigLoader] 파일을 열 수 없습니다\n";
            return terminals;
        }
        
        std::string content;
        try
        {
            content.resize(static_cast<std::size_t>(fileSize));
        }
        catch (const std::bad_alloc&)
        {
            std::cerr << "[XmlConfigLoader] 메모리 할당 실패\n";
            return terminals;
        }
        
        file.read(content.data(), static_cast<std::streamsize>(fileSize));
        file.close();
        
        // XXE 및 악성 패턴 검사
        if (!validateXmlContent(content))
        {
            std::cerr << "[XmlConfigLoader] 보안: 위험한 XML 패턴 감지\n";
            return terminals;
        }
        
        // XML 파싱 (정규식 없이 문자열 검색)
        std::size_t pos = 0;
        while (pos < content.size() && terminals.size() < MAX_TERMINALS)
        {
            std::size_t termStart = content.find("<terminal>", pos);
            if (termStart == std::string::npos)
            {
                break;
            }
            
            std::size_t termEnd = content.find("</terminal>", termStart);
            if (termEnd == std::string::npos)
            {
                break;
            }
            
            std::string terminalBlock = content.substr(
                termStart + 10,  // "<terminal>" 길이
                termEnd - termStart - 10);
            
            TerminalConfig config;
            
            config.aor = extractTag(terminalBlock, "aor");
            config.contact = extractTag(terminalBlock, "contact");
            config.ip = extractTag(terminalBlock, "ip");
            config.description = extractTag(terminalBlock, "description");
            
            // IP 주소 검증
            if (!isValidIpAddress(config.ip))
            {
                std::cerr << "[XmlConfigLoader] 잘못된 IP 주소: " << sanitizeForLog(config.ip) << "\n";
                pos = termEnd + 11;
                continue;
            }
            
            // AOR 검증
            if (!isValidAor(config.aor))
            {
                std::cerr << "[XmlConfigLoader] 잘못된 AOR: " << sanitizeForLog(config.aor) << "\n";
                pos = termEnd + 11;
                continue;
            }
            
            // Contact 검증
            if (!isValidContact(config.contact))
            {
                std::cerr << "[XmlConfigLoader] 잘못된 Contact: " << sanitizeForLog(config.contact) << "\n";
                pos = termEnd + 11;
                continue;
            }
            
            // 포트 파싱 및 검증
            std::string portStr = extractTag(terminalBlock, "port");
            if (!portStr.empty())
            {
                if (!parsePort(portStr, config.port))
                {
                    std::cerr << "[XmlConfigLoader] 잘못된 포트: " << portStr << "\n";
                    config.port = 5060;
                }
            }
            
            // Expires 파싱 및 검증
            std::string expiresStr = extractTag(terminalBlock, "expires");
            if (!expiresStr.empty())
            {
                if (!parseExpires(expiresStr, config.expiresSec))
                {
                    std::cerr << "[XmlConfigLoader] 잘못된 expires: " << expiresStr << "\n";
                    config.expiresSec = 3600;
                }
            }
            
            terminals.push_back(std::move(config));
            pos = termEnd + 11;  // "</terminal>" 길이
        }
        
        if (terminals.size() >= MAX_TERMINALS)
        {
            std::cerr << "[XmlConfigLoader] 최대 단말 수 초과 (" << MAX_TERMINALS << ")\n";
        }
        
        std::cout << "[XmlConfigLoader] " << terminals.size() << "개의 단말 정보 로드 완료\n";
        return terminals;
    }
    
    // SipCore에 단말 등록
    static std::size_t registerTerminals(SipCore& sipCore, 
                                          const std::vector<TerminalConfig>& terminals)
    {
        std::size_t count = 0;
        for (const auto& term : terminals)
        {
            if (sipCore.registerTerminal(term.aor, term.contact, 
                                          term.ip, term.port, term.expiresSec))
            {
                ++count;
                std::cout << "  - 등록: " << sanitizeForLog(term.aor);
                if (!term.description.empty())
                {
                    std::cout << " (" << sanitizeForLog(term.description) << ")";
                }
                std::cout << "\n";
            }
            else
            {
                std::cerr << "  - 등록 실패: " << sanitizeForLog(term.aor) << "\n";
            }
        }
        return count;
    }

private:
    // 파일 경로 보안 검증
    static bool validateFilePath(const std::string& path)
    {
        if (path.empty() || path.size() > 256)
        {
            return false;
        }
        
        // 널 바이트 체크
        if (path.find('\0') != std::string::npos)
        {
            return false;
        }
        
        // 경로를 소문자로 변환하여 패턴 검사
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        
        // 위험한 경로 패턴 체크
        const char* dangerousPatterns[] = {
            "..", "..\\" , "../",
            "%2e%2e", "%2e%2e%2f", "%2e%2e%5c",
            "/etc/", "/proc/", "/sys/", "/dev/",
            "c:\\windows", "\\\\"
        };
        
        for (const auto& pattern : dangerousPatterns)
        {
            if (lowerPath.find(pattern) != std::string::npos)
            {
                return false;
            }
        }
        
        // 허용된 확장자만
        std::filesystem::path p(path);
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        
        if (ext != ".xml")
        {
            return false;
        }
        
        return true;
    }
    
    // XML 콘텐츠 보안 검증 (XXE 방지)
    static bool validateXmlContent(const std::string& content)
    {
        // 위험한 XML 패턴 체크 (대소문자 무시)
        std::string upperContent = content;
        std::transform(upperContent.begin(), upperContent.end(), upperContent.begin(),
                      [](unsigned char c) { return std::toupper(c); });
        
        const char* dangerousPatterns[] = {
            "<!ENTITY",
            "<!DOCTYPE",
            "SYSTEM",
            "PUBLIC",
            "FILE://",
            "HTTP://",
            "HTTPS://",
            "FTP://",
            "EXPECT://",
            "PHP://",
            "DATA:"
        };
        
        for (const auto& pattern : dangerousPatterns)
        {
            if (upperContent.find(pattern) != std::string::npos)
            {
                return false;
            }
        }
        
        // 태그 깊이 체크 (간단한 버전)
        int depth = 0;
        int maxDepth = 0;
        
        for (std::size_t i = 0; i < content.size(); ++i)
        {
            if (content[i] == '<')
            {
                if (i + 1 < content.size())
                {
                    if (content[i + 1] == '/')
                    {
                        --depth;
                    }
                    else if (content[i + 1] != '?' && content[i + 1] != '!')
                    {
                        ++depth;
                        maxDepth = std::max(maxDepth, depth);
                    }
                }
            }
            else if (content[i] == '/' && i + 1 < content.size() && content[i + 1] == '>')
            {
                --depth;  // 자체 종료 태그
            }
            
            if (depth < 0 || maxDepth > static_cast<int>(MAX_TAG_DEPTH))
            {
                return false;
            }
        }
        
        return true;
    }
    
    // 로그 출력용 문자열 정화
    static std::string sanitizeForLog(const std::string& input)
    {
        std::string result;
        result.reserve(std::min(input.size(), static_cast<std::size_t>(100)));
        
        for (char c : input)
        {
            if (result.size() >= 100)
            {
                result += "...";
                break;
            }
            
            // 출력 가능한 ASCII만 허용, 위험 문자 필터링
            if (c >= 32 && c < 127 && c != '<' && c != '>')
            {
                result += c;
            }
            else
            {
                result += '?';
            }
        }
        
        return result;
    }
    
    // IPv4 주소 검증 (선행 0 검사 포함)
    static bool isValidIpAddress(const std::string& ip)
    {
        if (ip.empty() || ip.size() > 15)
        {
            return false;
        }
        
        int octets = 0;
        int num = 0;
        bool hasDigit = false;
        int digitCount = 0;
        bool leadingZero = false;
        
        for (char c : ip)
        {
            if (c == '.')
            {
                if (!hasDigit || num > 255)
                {
                    return false;
                }
                // 선행 0 검사: "00", "01", "001" 등은 거부 (단, "0" 자체는 허용)
                if (leadingZero && digitCount > 1)
                {
                    return false;
                }
                octets++;
                num = 0;
                hasDigit = false;
                digitCount = 0;
                leadingZero = false;
            }
            else if (c >= '0' && c <= '9')
            {
                // 첫 자리가 0인지 체크
                if (!hasDigit && c == '0')
                {
                    leadingZero = true;
                }
                num = num * 10 + (c - '0');
                hasDigit = true;
                ++digitCount;
                if (num > 255 || digitCount > 3)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        
        // 마지막 옥텟 검사
        if (!hasDigit || num > 255)
        {
            return false;
        }
        // 선행 0 검사: "00", "01", "001" 등은 거부 (단, "0" 자체는 허용)
        if (leadingZero && digitCount > 1)
        {
            return false;
        }
        
        return octets == 3;
    }
    
    // AOR 형식 검증 (강화된 버전)
    static bool isValidAor(const std::string& aor)
    {
        if (aor.size() < 7 || aor.size() > 256)
        {
            return false;
        }
        
        // "sip:" 또는 "sips:" 프리픽스
        std::size_t userStart = 0;
        if (aor.substr(0, 4) == "sip:")
        {
            userStart = 4;
        }
        else if (aor.substr(0, 5) == "sips:")
        {
            userStart = 5;
        }
        else
        {
            return false;
        }
        
        auto atPos = aor.find('@');
        if (atPos == std::string::npos || atPos <= userStart)
        {
            return false;
        }
        
        // 사용자 부분에 허용되지 않는 문자 검사
        for (std::size_t i = userStart; i < atPos; ++i)
        {
            char c = aor[i];
            if (!std::isalnum(static_cast<unsigned char>(c)) && 
                c != '-' && c != '_' && c != '.')
            {
                return false;
            }
        }
        
        return true;
    }
    
    // Contact URI 검증
    static bool isValidContact(const std::string& contact)
    {
        if (contact.empty() || contact.size() > MAX_STRING_LENGTH)
        {
            return false;
        }
        
        // "sip:" 또는 "sips:" 프리픽스 필수
        if (contact.substr(0, 4) != "sip:" && contact.substr(0, 5) != "sips:")
        {
            return false;
        }
        
        // 위험 문자 검사 (CRLF 인젝션, 널 바이트)
        for (char c : contact)
        {
            if (c == '\r' || c == '\n' || c == '\0' ||
                static_cast<unsigned char>(c) < 0x20)
            {
                return false;
            }
        }
        
        return true;
    }
    
    // 포트 파싱 (std::from_chars 사용 - 예외 없음)
    static bool parsePort(std::string_view portStr, uint16_t& outPort)
    {
        if (portStr.empty() || portStr.size() > 5)
        {
            return false;
        }
        
        unsigned int val = 0;
        auto [ptr, ec] = std::from_chars(portStr.data(), 
                                          portStr.data() + portStr.size(), val);
        
        if (ec != std::errc{} || ptr != portStr.data() + portStr.size())
        {
            return false;  // 파싱 실패 또는 남은 문자가 있음
        }
        
        if (val == 0 || val > 65535)
        {
            return false;
        }
        
        outPort = static_cast<uint16_t>(val);
        return true;
    }
    
    // Expires 파싱 (std::from_chars 사용 - 예외 없음)
    static bool parseExpires(std::string_view expiresStr, int& outExpires)
    {
        if (expiresStr.empty() || expiresStr.size() > 10)
        {
            return false;
        }
        
        int val = 0;
        auto [ptr, ec] = std::from_chars(expiresStr.data(), 
                                          expiresStr.data() + expiresStr.size(), val);
        
        if (ec != std::errc{} || ptr != expiresStr.data() + expiresStr.size())
        {
            return false;
        }
        
        if (val < 0)
        {
            outExpires = 0;
        }
        else if (val > SipConstants::MAX_EXPIRES_SEC)
        {
            outExpires = SipConstants::MAX_EXPIRES_SEC;
        }
        else
        {
            outExpires = val;
        }
        return true;
    }
    
    // XML 태그 추출 (최적화된 버전 - 정규식 없이, 엔티티 디코딩 포함)
    static std::string extractTag(const std::string& xml, const std::string& tag)
    {
        std::string openTag = "<" + tag + ">";
        std::string closeTag = "</" + tag + ">";
        
        auto startPos = xml.find(openTag);
        if (startPos == std::string::npos)
        {
            return "";
        }
        
        startPos += openTag.length();
        auto endPos = xml.find(closeTag, startPos);
        if (endPos == std::string::npos)
        {
            return "";
        }
        
        // 추출 문자열 길이 제한
        if (endPos - startPos > MAX_STRING_LENGTH)
        {
            return "";
        }
        
        std::string value = xml.substr(startPos, endPos - startPos);
        value = trim(value);
        
        // XML 엔티티 디코딩
        return decodeXmlEntities(value);
    }
    
    // XML 엔티티 디코딩
    static std::string decodeXmlEntities(const std::string& input)
    {
        std::string result;
        result.reserve(input.size());
        
        for (std::size_t i = 0; i < input.size(); ++i)
        {
            if (input[i] == '&')
            {
                auto semicolon = input.find(';', i);
                if (semicolon != std::string::npos && semicolon - i < 10)
                {
                    std::string entity = input.substr(i + 1, semicolon - i - 1);
                    
                    if (entity == "lt")
                    {
                        result += '<';
                    }
                    else if (entity == "gt")
                    {
                        result += '>';
                    }
                    else if (entity == "amp")
                    {
                        result += '&';
                    }
                    else if (entity == "apos")
                    {
                        result += '\'';
                    }
                    else if (entity == "quot")
                    {
                        result += '"';
                    }
                    else if (entity.size() > 1 && entity[0] == '#')
                    {
                        // 숫자 엔티티 (&#60; 등)
                        int charCode = 0;
                        std::string_view numStr(entity.data() + 1, entity.size() - 1);
                        auto [ptr, ec] = std::from_chars(
                            numStr.data(), numStr.data() + numStr.size(), charCode);
                        
                        if (ec == std::errc{} && charCode > 0 && charCode < 128)
                        {
                            result += static_cast<char>(charCode);
                        }
                        else
                        {
                            result += input.substr(i, semicolon - i + 1);
                        }
                    }
                    else
                    {
                        result += input.substr(i, semicolon - i + 1);
                    }
                    
                    i = semicolon;
                    continue;
                }
            }
            
            result += input[i];
        }
        
        return result;
    }
    
    static std::string trim(std::string_view s)
    {
        constexpr std::string_view ws = " \t\r\n";
        const auto start = s.find_first_not_of(ws);
        if (start == std::string_view::npos)
        {
            return "";
        }
        const auto end = s.find_last_not_of(ws);
        return std::string(s.substr(start, end - start + 1));
    }
};
