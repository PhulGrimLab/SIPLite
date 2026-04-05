#include "UdpServer.h"
#include "TcpServer.h"
#include "TlsServer.h"
#include "UdpPacket.h"
#include "XmlConfigLoader.h"
#include "ConsoleInterface.h"
#include "Logger.h"

#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace // 현재 파일 내에서만 사용되는 전역 변수 선언
{
    // volatile sig_atomic_t 사용 (시그널 핸들러에서 안전)
    volatile std::sig_atomic_t g_signalReceived = 0;
    std::atomic<bool> g_terminate(false);
}

// extern "C" 시그널 핸들러 (C 링키지 필수)
extern "C" void signalHandler(int signo) 
{
    g_signalReceived = signo;
}

namespace
{
    // 시그널 체크 함수 (메인 스레드에서 호출)
    void checkSignal()
    {
        int sig = g_signalReceived;     // TOCTOU 문제 방지를 위해 로컬 복사
        /*
        TOCTOU (Time-of-check to time-of-use) 문제가 발생할 수 있습니다:

        첫 번째 비교(g_signalReceived == SIGINT)를 수행하는 시점과
        두 번째 비교(g_signalReceived == SIGTERM)를 수행하는 시점 사이에
        시그널 핸들러가 값을 변경할 수 있습니다.
        */
       
        if (sig == SIGINT || sig == SIGTERM)
        {
            g_signalReceived = 0;  // 리셋
            g_terminate.store(true, std::memory_order_release);
        }
    }
}


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
        
        if (!XmlConfigLoader::validateFilePath(configPath))
        {
            std::cerr << "[오류] 잘못된 설정 파일 경로\n";
            return 1;
        }
    }


    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║              SIPLite Server v0.1 시작 중...              ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";

    // 로그 초기화 및 시작 로그
    int retentionDays = 7; // 기본 보존기간: 7일
    const char* env = std::getenv("SIPLITE_LOG_RETENTION_DAYS");
    if (env)
    {
        try
        {
            int v = std::stoi(env);
            if (v < 0) v = 0;
            retentionDays = v;
        }
        catch (...)
        {
            std::cerr << "[Logger] Invalid SIPLITE_LOG_RETENTION_DAYS='" << env << "', using default " << retentionDays << "\n";
        }
    }

    Logger::instance().init("logs", retentionDays);
    Logger::instance().info("SIPLite Server v0.1 시작 중");
    Logger::instance().info("[Logger] Log retention days: " + std::to_string(retentionDays));
    UdpServer udpServer;
    const std::string bindIp = "0.0.0.0";
    const uint16_t bindPort = 5060;     // 표준 SIP 포트

    // 워커 스레드 수: CPU 논리 코어 수 기반 자동 설정
    // 수신/콘솔/메인 스레드를 고려하여 (논리코어 수 - 1), 최소 1개, 최대 8개
    unsigned int hwThreads = std::thread::hardware_concurrency();
    if (hwThreads == 0) hwThreads = 2; // 감지 실패 시 보수적 기본값
    std::size_t workerCount = std::max<std::size_t>(1, std::min<std::size_t>(hwThreads - 1, 8));
    Logger::instance().info("[초기화] CPU 논리 코어: " + std::to_string(hwThreads)
                         + ", 워커 스레드: " + std::to_string(workerCount));

    // 단말 설정 로드
    std::cout << "[초기화] 단말 설정 파일 로드 중: " << configPath << "\n";
    auto terminals = XmlConfigLoader::loadTerminals(configPath);
    
    // UDP 서버 시작
    if (!udpServer.start(bindIp, bindPort, workerCount)) 
    {
        Logger::instance().error("[오류] UDP 서버 시작 실패");
        return 1;
    }

    // TCP 서버 시작 (UDP 서버의 SipCore를 공유)
    TcpServer tcpServer(udpServer.sipCore());
    if (!tcpServer.start(bindIp, bindPort, workerCount))
    {
        // TCP 시작 실패는 치명적이지 않음 — UDP만으로 동작
        Logger::instance().error("[경고] TCP 서버 시작 실패 (UDP만 사용)");
        std::cerr << "[경고] TCP 서버 시작 실패 (UDP만 사용)\n";
    }
    else
    {
        std::cout << "[서버] TCP 서버 실행 중 (포트: " << bindPort << ")\n";
    }

    TlsServer tlsServer(udpServer.sipCore());
    bool tlsStarted = false;
    const char* tlsEnableEnv = std::getenv("SIPLITE_TLS_ENABLE");
    const bool tlsEnabled = (tlsEnableEnv != nullptr) &&
        (std::string(tlsEnableEnv) == "1" || std::string(tlsEnableEnv) == "true");
    if (tlsEnabled)
    {
        uint16_t tlsPort = 5061;
        if (const char* tlsPortEnv = std::getenv("SIPLITE_TLS_PORT"))
        {
            try
            {
                int parsed = std::stoi(tlsPortEnv);
                if (parsed > 0 && parsed <= 65535)
                {
                    tlsPort = static_cast<uint16_t>(parsed);
                }
            }
            catch (...)
            {
                Logger::instance().error("[경고] SIPLITE_TLS_PORT 값이 잘못되어 기본값 5061 사용");
            }
        }

        const char* certFile = std::getenv("SIPLITE_TLS_CERT_FILE");
        const char* keyFile = std::getenv("SIPLITE_TLS_KEY_FILE");
        if (certFile != nullptr && keyFile != nullptr &&
            std::strlen(certFile) > 0 && std::strlen(keyFile) > 0)
        {
            tlsStarted = tlsServer.start(bindIp, tlsPort, workerCount, certFile, keyFile);
            if (!tlsStarted)
            {
                Logger::instance().error("[경고] TLS 서버 시작 실패 (UDP/TCP만 사용)");
                std::cerr << "[경고] TLS 서버 시작 실패 (UDP/TCP만 사용)\n";
            }
            else
            {
                udpServer.sipCore().setLocalAddressForTransport(TransportType::TLS, bindIp, tlsPort);
                std::cout << "[서버] TLS 서버 실행 중 (포트: " << tlsPort << ")\n";
            }
        }
        else
        {
            Logger::instance().error("[경고] TLS 활성화 요청이 있었지만 인증서/키 경로가 없음");
            std::cerr << "[경고] TLS 활성화 요청이 있었지만 인증서/키 경로가 없음\n";
        }
    }

    // 전송 프로토콜 라우팅 콜백 설정
    // TLS 연결이 있으면 TLS로, 없으면 TCP, 마지막으로 UDP로 전송
    udpServer.sipCore().setSender(
        [&udpServer, &tcpServer, &tlsServer, &tlsStarted](const std::string& ip,
                                                          uint16_t port,
                                                          const std::string& data,
                                                          TransportType transport) -> bool {
            if (transport == TransportType::TLS)
            {
                return tlsStarted && tlsServer.sendTo(ip, port, data);
            }
            if (transport == TransportType::TCP)
            {
                return tcpServer.sendTo(ip, port, data);
            }
            return udpServer.sendTo(ip, port, data);
        });

    // 단말 등록
    if (!terminals.empty())
    {
        std::cout << "\n[초기화] 단말 등록 중...\n";
        std::size_t registered = XmlConfigLoader::registerTerminals(
            udpServer.sipCore(), terminals);
        std::cout << "[초기화] " << registered << "개의 단말이 등록되었습니다.\n";
    }
    else
    {
        std::cout << "[초기화] 등록할 단말 정보가 없습니다.\n";
    }

    std::cout << "\n[서버] UDP 서버 실행 중 (포트: " << bindPort << ")\n";

    // 콘솔 인터페이스 시작
    ConsoleInterface console(udpServer, &tcpServer, tlsStarted ? &tlsServer : nullptr);
    console.start();

    // 메인 루프: 콘솔 종료 요청 또는 SIGINT 대기
    // Timer C 및 기타 정리 작업을 주기적으로 수행
    auto lastCleanup = std::chrono::steady_clock::now();
    constexpr auto cleanupInterval = std::chrono::seconds(1);

    while (!g_terminate.load(std::memory_order_acquire) && 
           !console.isExitRequested()) 
    {
        // 시그널 체크 (시그널 핸들러는 최소 작업만)
        checkSignal();

        auto now = std::chrono::steady_clock::now();
        if (now - lastCleanup >= cleanupInterval)
        {
            // RFC 3261 §16.7 Timer C: INVITE 타임아웃 확인 (180초)
            udpServer.sipCore().cleanupTimerC();
            // 만료된 등록 및 stale 통화/트랜잭션 정리
            udpServer.sipCore().cleanupExpiredRegistrations();
            udpServer.sipCore().cleanupStaleCalls();
            udpServer.sipCore().cleanupStaleTransactions();
            lastCleanup = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    Logger::instance().info("[서버] 종료 중...");
    
    console.stop();
    if (tlsStarted)
    {
        tlsServer.stop();
    }
    tcpServer.stop();
    udpServer.stop();
    
    Logger::instance().info("[서버] 정상 종료되었습니다.");

    // 로그 파일 정리
    Logger::instance().shutdown();
    return 0;
}
