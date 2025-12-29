#include "ConsoleInterface.h"

#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>

ConsoleInterface::~ConsoleInterface()
{
    stop();
}

void ConsoleInterface::start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true,
        std::memory_order_acq_rel))
    {
        return;  // 이미 실행 중
    }

    // 입력 스레드와 처리 스레드 분리
    inputThread_ = std::thread(&ConsoleInterface::inputLoop, this);
    consoleThread_ = std::thread(&ConsoleInterface::consoleLoop, this);
}

void ConsoleInterface::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false,
        std::memory_order_acq_rel))
    {
        return;  // 이미 중지됨
    }

    // 조건변수로 대기 중인 스레드 깨우기
    {
        std::lock_guard<std::mutex> lock(inputMutex_);
        inputReady_ = true;
    }
    inputCv_.notify_all();

    // 처리 스레드는 안전하게 join
    if (consoleThread_.joinable())
    {
        consoleThread_.join();
    }

    // 입력 스레드는 블로킹 중일 수 있으므로 detach
    if (inputThread_.joinable())
    {
        inputThread_.detach();
    }
}

bool ConsoleInterface::isExitRequested() const
{
    return exitRequested_.load(std::memory_order_acquire);
}

void ConsoleInterface::inputLoop()
{
    while (running_.load(std::memory_order_acquire))
    {
        std::string line;
        if (!std::getline(std::cin, line))
        {
            // EOF - 종료 요청으로 처리
            {
                std::lock_guard<std::mutex> lock(inputMutex_);
                currentInput_ = "exit";
                inputReady_ = true;
            }
            inputCv_.notify_one();
            break;
        }

        {
            std::lock_guard<std::mutex> lock(inputMutex_);
            currentInput_ = std::move(line);
            inputReady_ = true;
        }
        inputCv_.notify_one();

        // 처리 완료 대기
        {
            std::unique_lock<std::mutex> lock(inputMutex_);
            inputCv_.wait(lock, [this] {
                return !inputReady_ || !running_.load(std::memory_order_acquire);
            });
        }
    }
}

void ConsoleInterface::consoleLoop()
{
    showWelcome();

    while (running_.load(std::memory_order_acquire))
    {
        showMenu();
        std::cout << "\n명령 입력: " << std::flush;

        // 입력 대기
        std::string input;
        {
            std::unique_lock<std::mutex> lock(inputMutex_);
            inputCv_.wait(lock, [this] {
                return inputReady_ || !running_.load(std::memory_order_acquire);
            });

            if (!running_.load(std::memory_order_acquire))
            {
                break;
            }

            input = std::move(currentInput_);
            inputReady_ = false;
        }
        inputCv_.notify_one();  // 입력 스레드 깨우기

        input = trim(input);
        if (!input.empty())
        {
            processCommand(input);
        }
    }
}

void ConsoleInterface::showWelcome()
{
    static const std::string welcomeMessage =
        "\n"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║           SIPLite Server v0.1 - 콘솔 인터페이스           ║\n"
        "╚══════════════════════════════════════════════════════════╝\n"
        "\n";
    std::cout << welcomeMessage;
}

void ConsoleInterface::showMenu()
{
    static const std::string menuMessage =
        "\n"
        "┌──────────────────────────────────────────────────────────┐\n"
        "│                      메뉴 선택                           │\n"
        "├──────────────────────────────────────────────────────────┤\n"
        "│  1. 서버 상태 확인                                       │\n"
        "│  2. 등록된 단말 현황                                     │\n"
        "│  3. 활성 통화 현황                                       │\n"
        "│  4. 서버 종료                                            │\n"
        "│  h. 도움말                                               │\n"
        "└──────────────────────────────────────────────────────────┘\n";
    std::cout << menuMessage;
}

bool ConsoleInterface::validateConsoleInput(const std::string& input)
{
    if (input.size() > 64)
        return false;
    for (char c : input)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != ' ' && c != '-' && c != '_' && c != '?' && c != '.')
        {
            return false;
        }
    }
    return true;
}

std::string ConsoleInterface::sanitizeOutput(const std::string& input, std::size_t maxLen)
{
    std::string result;
    result.reserve(std::min(input.size(), maxLen));

    for (char c : input)
    {
        if (result.size() >= maxLen)
        {
            result += "...";
            break;
        }

        if (c >= 32 && c < 127)
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

void ConsoleInterface::processCommand(const std::string& cmd)
{
    if (!validateConsoleInput(cmd))
    {
        std::cout << "\n[오류] 잘못된 입력입니다.\n";
        return;
    }

    if (cmd == "1" || cmd == "status")
    {
        showServerStatus();
    }
    else if (cmd == "2" || cmd == "terminals" || cmd == "reg")
    {
        showRegisteredTerminals();
    }
    else if (cmd == "3" || cmd == "calls")
    {
        showActiveCalls();
    }
    else if (cmd == "4" || cmd == "exit" || cmd == "quit" || cmd == "q")
    {
        handleExit();
    }
    else if (cmd == "h" || cmd == "help" || cmd == "?")
    {
        showHelp();
    }
    else
    {
        std::cout << "\n[오류] 알 수 없는 명령입니다. 'h'를 입력하여 도움말을 확인하세요.\n";
    }
}

void ConsoleInterface::showServerStatus()
{
    auto& sipCore = server_.sipCore();
    const auto stats = sipCore.getStats();

    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::array<char, 32> timeBuf{};
    struct tm tmBuf{};
#ifdef _WIN32
    localtime_s(&tmBuf, &time);
#else
    localtime_r(&time, &tmBuf);
#endif
    if (std::strftime(timeBuf.data(), timeBuf.size(),
                      "%Y-%m-%d %H:%M:%S", &tmBuf) == 0)
    {
        std::snprintf(timeBuf.data(), timeBuf.size(), "N/A");
    }

    std::ostringstream oss;
    oss << "\n"
        << "┌──────────────────────────────────────────────────────────┐\n"
        << "│                     서버 상태                            │\n"
        << "├──────────────────────────────────────────────────────────┤\n"
        << "│  서버 상태      : " << std::left << std::setw(38)
        << "실행 중 ✓" << "│\n"
        << "│  등록된 단말 수 : " << std::left << std::setw(38)
        << stats.registrationCount << "│\n"
        << "│  활성 등록 수   : " << std::left << std::setw(38)
        << stats.activeRegistrationCount << "│\n"
        << "│  활성 통화 수   : " << std::left << std::setw(38)
        << stats.activeCallCount << "│\n"
        << "│  현재 시간      : " << std::left << std::setw(38)
        << timeBuf.data() << "│\n"
        << "└──────────────────────────────────────────────────────────┘\n";

    std::cout << oss.str();
}

void ConsoleInterface::showRegisteredTerminals()
{
    auto& sipCore = server_.sipCore();
    const auto registrations = sipCore.getAllRegistrations();
    const auto now = std::chrono::steady_clock::now();

    std::ostringstream oss;
    oss << "\n"
        << "┌──────────────────────────────────────────────────────────────────────────────┐\n"
        << "│                            등록된 단말 현황                                  │\n"
        << "├──────────────────────────────────────────────────────────────────────────────┤\n";

    if (registrations.empty())
    {
        oss << "│  등록된 단말이 없습니다.                                                     │\n";
    }
    else
    {
        oss << "│  번호   AOR                            IP:Port              만료까지         │\n"
            << "├──────────────────────────────────────────────────────────────────────────────┤\n";

        int idx = 1;
        for (const auto& reg : registrations)
        {
            const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
                reg.expiresAt - now).count();

            std::array<char, 32> ipPortBuf{};
            std::snprintf(ipPortBuf.data(), ipPortBuf.size(),
                         "%s:%u", reg.ip.c_str(), reg.port);

            oss << "│  " << std::setw(5) << std::left << idx
                << "  " << std::setw(30) << std::left << truncate(reg.aor, 28)
                << "  " << std::setw(20) << std::left << ipPortBuf.data()
                << "  " << std::setw(12) << std::left << formatRemainingTime(remaining)
                << "│\n";
            ++idx;
        }
    }

    oss << "├──────────────────────────────────────────────────────────────────────────────┤\n"
        << "│  총 " << std::left << std::setw(3) << registrations.size()
        << "개의 단말이 등록되어 있습니다.                                           │\n"
        << "└──────────────────────────────────────────────────────────────────────────────┘\n";

    std::cout << oss.str();
}

void ConsoleInterface::showActiveCalls()
{
    auto& sipCore = server_.sipCore();
    const auto calls = sipCore.getAllActiveCalls();
    const auto now = std::chrono::steady_clock::now();

    std::ostringstream oss;
    oss << "\n"
        << "┌──────────────────────────────────────────────────────────────────────────────┐\n"
        << "│                            활성 통화 현황                                    │\n"
        << "├──────────────────────────────────────────────────────────────────────────────┤\n";

    if (calls.empty())
    {
        oss << "│  진행 중인 통화가 없습니다.                                                  │\n";
    }
    else
    {
        oss << "│  번호   Call-ID                  발신자         수신자         상태          │\n"
            << "├──────────────────────────────────────────────────────────────────────────────┤\n";

        int idx = 1;
        for (const auto& call : calls)
        {
            const auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - call.startTime).count();

            std::string status = call.confirmed
                ? "통화중 " + formatDuration(duration)
                : "연결중";

            oss << "│  " << std::setw(5) << std::left << idx
                << "  " << std::setw(22) << std::left << truncate(call.callId, 20)
                << "  " << std::setw(13) << std::left << truncate(extractUser(call.fromUri), 11)
                << "  " << std::setw(13) << std::left << truncate(extractUser(call.toUri), 11)
                << "  " << std::setw(12) << std::left << status
                << "│\n";
            ++idx;
        }
    }

    oss << "├──────────────────────────────────────────────────────────────────────────────┤\n"
        << "│  총 " << std::left << std::setw(3) << calls.size()
        << "개의 통화가 진행 중입니다.                                               │\n"
        << "└──────────────────────────────────────────────────────────────────────────────┘\n";

    std::cout << oss.str();
}

void ConsoleInterface::showHelp()
{
    static const std::string helpMessage =
        "\n"
        "┌──────────────────────────────────────────────────────────┐\n"
        "│                        도움말                            │\n"
        "├──────────────────────────────────────────────────────────┤\n"
        "│  명령어:                                                 │\n"
        "│    1, status    - 서버 상태 확인                         │\n"
        "│    2, reg       - 등록된 단말 현황                       │\n"
        "│    3, calls     - 활성 통화 현황                         │\n"
        "│    4, exit, q   - 서버 종료                              │\n"
        "│    h, help, ?   - 이 도움말 표시                         │\n"
        "│                                                          │\n"
        "│  Ctrl+C로도 서버를 종료할 수 있습니다.                   │\n"
        "└──────────────────────────────────────────────────────────┘\n";
    std::cout << helpMessage;
}

void ConsoleInterface::handleExit()
{
    static const std::string exitMessage =
        "\n"
        "┌──────────────────────────────────────────────────────────┐\n"
        "│                     서버 종료                            │\n"
        "├──────────────────────────────────────────────────────────┤\n"
        "│  서버를 종료합니다...                                    │\n"
        "└──────────────────────────────────────────────────────────┘\n";
    std::cout << exitMessage;

    // 원자적으로 상태 변경
    exitRequested_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
}

std::string ConsoleInterface::trim(std::string_view s)
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

std::string ConsoleInterface::truncate(std::string_view s, std::size_t maxLen)
{
    if (s.length() <= maxLen)
    {
        return std::string(s);
    }
    if (maxLen < 3)
    {
        return std::string(s.substr(0, maxLen));
    }
    return std::string(s.substr(0, maxLen - 2)) + "..";
}

std::string ConsoleInterface::extractUser(std::string_view uri)
{
    const auto colonPos = uri.find(':');
    const auto atPos = uri.find('@');

    if (colonPos != std::string_view::npos &&
        atPos != std::string_view::npos &&
        colonPos < atPos)
    {
        return std::string(uri.substr(colonPos + 1, atPos - colonPos - 1));
    }
    return std::string(uri);
}

std::string ConsoleInterface::formatRemainingTime(long remaining)
{
    if (remaining <= 0)
    {
        return "만료됨";
    }

    std::array<char, 16> buf{};
    if (remaining < 60)
    {
        std::snprintf(buf.data(), buf.size(), "%ld초", remaining);
    }
    else if (remaining < 3600)
    {
        std::snprintf(buf.data(), buf.size(), "%ld분", remaining / 60);
    }
    else
    {
        std::snprintf(buf.data(), buf.size(), "%ld시간", remaining / 3600);
    }
    return std::string(buf.data());
}

std::string ConsoleInterface::formatDuration(long seconds)
{
    std::array<char, 24> buf{};
    if (seconds < 60)
    {
        std::snprintf(buf.data(), buf.size(), "%ld초", seconds);
    }
    else
    {
        std::snprintf(buf.data(), buf.size(), "%ld분 %ld초",
                     seconds / 60, seconds % 60);
    }
    return std::string(buf.data());
}
