#include "UdpServer.h"
#include "UdpPacket.h"
#include "XmlConfigLoader.h"
#include "ConsoleInterface.h"

#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <cctype>

namespace {
    // volatile sig_atomic_t 사용 (시그널 핸들러에서 안전)
    volatile std::sig_atomic_t g_signalReceived = 0;
    std::atomic<bool> g_terminate(false);
}

// extern "C" 시그널 핸들러 (C 링키지 필수)
extern "C" void signalHandler(int signo) 
{
    g_signalReceived = signo;
}

namespace {
    // 시그널 체크 함수 (메인 스레드에서 호출)
    void checkSignal()
    {
        int sig = g_signalReceived;
        if (sig == SIGINT || sig == SIGTERM)
        {
            g_signalReceived = 0;  // 리셋
            g_terminate.store(true, std::memory_order_release);
        }
    }
    
    // 설정 파일 경로 검증 (보안 강화 버전)
    bool validateConfigPath(const std::string& path)
    {
        // 빈 경로 체크
        if (path.empty() || path.size() > 256)
        {
            std::cerr << "[오류] 잘못된 경로 길이\n";
            return false;
        }
        
        // 널 바이트 체크
        if (path.find('\0') != std::string::npos)
        {
            std::cerr << "[오류] 경로에 널 바이트 포함\n";
            return false;
        }
        
        // 다양한 경로 순회 패턴 체크
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
                      [](unsigned char c) { return std::tolower(c); });
        
        const char* dangerousPatterns[] = {
            "..", "..\\" , "../",
            "%2e%2e", "%2e%2e%2f", "%2e%2e%5c",
            "%252e",  // 이중 인코딩
            "....//", "....\\\\" ,
            "/etc/", "/proc/", "/sys/", "/dev/",
            "c:\\windows", "\\\\"
        };
        
        for (const auto& pattern : dangerousPatterns)
        {
            if (lowerPath.find(pattern) != std::string::npos)
            {
                std::cerr << "[오류] 보안: 허용되지 않은 경로 패턴\n";
                return false;
            }
        }
        
        try
        {
            std::filesystem::path p(path);
            
            // 확장자 검증
            std::string ext = p.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                          [](unsigned char c) { return std::tolower(c); });
            
            if (ext != ".xml")
            {
                std::cerr << "[오류] XML 파일만 허용됩니다\n";
                return false;
            }
            
            // 심볼릭 링크 체크
            std::error_code ec;
            if (std::filesystem::exists(path, ec) && !ec)
            {
                if (std::filesystem::is_symlink(path, ec))
                {
                    std::cerr << "[오류] 보안: 심볼릭 링크 비허용\n";
                    return false;
                }
            }
            
            return true;
        }
        catch (const std::exception& e)
        {
            std::cerr << "[오류] 경로 검증 실패\n";
            return false;
        }
    }
};

int main(int argc, char* argv[]) 
{
    // 시그널 핸들러 설정 (sigaction 사용 권장하나 이식성 위해 signal 사용)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // 설정 파일 경로 (인자로 지정 가능)
    std::string configPath = "config/terminals.xml";
    if (argc > 1)
    {
        configPath = argv[1];
        
        if (!validateConfigPath(configPath))
        {
            std::cerr << "[오류] 잘못된 설정 파일 경로\n";
            return 1;
        }
    }

    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║              SIPLite Server v0.1 시작 중...               ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";

    UdpServer server;
    const std::string bindIp = "0.0.0.0";
    const uint16_t bindPort = 5060;
    const std::size_t workerCount = 4;

    // 단말 설정 로드
    std::cout << "[초기화] 단말 설정 파일 로드 중: " << configPath << "\n";
    auto terminals = XmlConfigLoader::loadTerminals(configPath);
    
    // 서버 시작
    if (!server.start(bindIp, bindPort, workerCount)) 
    {
        std::cerr << "[오류] 서버 시작 실패\n";
        return 1;
    }

    // 단말 등록
    if (!terminals.empty())
    {
        std::cout << "\n[초기화] 단말 등록 중...\n";
        std::size_t registered = XmlConfigLoader::registerTerminals(
            server.sipCore(), terminals);
        std::cout << "[초기화] " << registered << "개의 단말이 등록되었습니다.\n";
    }
    else
    {
        std::cout << "[초기화] 등록할 단말 정보가 없습니다.\n";
    }

    std::cout << "\n[서버] UDP 서버 실행 중 (포트: " << bindPort << ")\n";

    // 콘솔 인터페이스 시작
    ConsoleInterface console(server);
    console.start();

    // 메인 루프: 콘솔 종료 요청 또는 SIGINT 대기
    while (!g_terminate.load(std::memory_order_acquire) && 
           !console.isExitRequested()) 
    {
        // 시그널 체크 (시그널 핸들러는 최소 작업만)
        checkSignal();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "\n[서버] 종료 중...\n";
    
    console.stop();
    server.stop();
    
    std::cout << "[서버] 정상 종료되었습니다.\n\n";
    return 0;
}
