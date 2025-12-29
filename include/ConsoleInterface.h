#pragma once

#include "UdpServer.h"
#include "SipCore.h"

#include <atomic>
#include <iostream>
#include <iomanip>
#include <string>
#include <string_view>
#include <thread>
#include <chrono>
#include <sstream>
#include <mutex>
#include <condition_variable>
#include <array>
#include <cstdio>
#include <ctime>    // for localtime_r

// ================================
// 콘솔 인터페이스
// ================================

class ConsoleInterface
{
public:
    explicit ConsoleInterface(UdpServer& server)
        : server_(server)
        , running_(false)
        , exitRequested_(false)
        , inputReady_(false)
    {}
    
    ~ConsoleInterface();
    
    // 복사/이동 금지
    ConsoleInterface(const ConsoleInterface&) = delete;
    ConsoleInterface& operator=(const ConsoleInterface&) = delete;
    ConsoleInterface(ConsoleInterface&&) = delete;
    ConsoleInterface& operator=(ConsoleInterface&&) = delete;
    
    void start();
    void stop();

    // 외부에서 종료 요청 확인
    bool isExitRequested() const;

private:
    // 입력 전용 스레드 (블로킹 I/O 분리)
    void inputLoop();
    
    // 명령 처리 스레드
    void consoleLoop();
    
    void showWelcome();
    
    void showMenu();
    
    // 콘솔 입력 검증
    static bool validateConsoleInput(const std::string& input);
    
    // 출력용 문자열 정화 (로그 인젝션 방지)
    static std::string sanitizeOutput(const std::string& input, std::size_t maxLen = 50);
    
    void processCommand(const std::string& cmd);
    
    void showServerStatus();
    void showRegisteredTerminals();
    void showActiveCalls();
    void showHelp();
    void handleExit();
    
    // ================================
    // 유틸리티 함수들
    // ================================
    
    static std::string trim(std::string_view s);
    static std::string truncate(std::string_view s, std::size_t maxLen);
    static std::string extractUser(std::string_view uri);
    static std::string formatRemainingTime(long remaining);
    static std::string formatDuration(long seconds);
    
private:
    UdpServer& server_;
    
    // 스레드 제어
    std::atomic<bool> running_;
    std::atomic<bool> exitRequested_;
    std::thread consoleThread_;
    std::thread inputThread_;
    
    // 입력 동기화
    std::mutex inputMutex_;
    std::condition_variable inputCv_;
    std::string currentInput_;
    bool inputReady_;
};
