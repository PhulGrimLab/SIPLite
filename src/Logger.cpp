#include "Logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <mutex>

Logger& Logger::instance()
{
    static Logger inst;
    return inst;
}

Logger::Logger()
    : retentionDays_(7)
{
}

Logger::~Logger()
{
    shutdown();
}

static std::string hourString(std::chrono::system_clock::time_point tp)
{
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm {};
    localtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H", &tm);
    return std::string(buf);
}

static std::string timeStamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm {};
    localtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void Logger::rotateIfNeeded()
{
    auto now = std::chrono::system_clock::now();
    std::string h = hourString(now);

    // 현재 시간대와 다른 시간대 로그 파일로 전환 필요
    if (h != currentHour_)
    {
        if (ofs_.is_open())
        { 
            ofs_.close();
        }

        try
        {
            // 로그 디렉토리 존재 여부 확인 및 생성
            if (!std::filesystem::exists(dir_))
            {
                std::filesystem::create_directories(dir_);
            }

            std::string filename = dir_ + "/siplite_" + h + ".txt";
            ofs_.open(filename, std::ios::app | std::ios::out);
            if (!ofs_.is_open())
            {
                std::cerr << "[Logger] Failed to open log file: " << filename << "\n";
                currentHour_.clear();
                return;
            }
                        
            currentHour_ = h;

            // 보존 정책 적용: 로테이션 발생 시 오래된 로그 삭제
            purgeOldLogs();
        }
        catch(const std::exception& e)
        {
            // 로거 내부에서 예외가 전파되면 프로그램 안정성에 영향이 있으므로
            // 여기서는 콘솔에 출력하고 파일 로깅은 건너뛴다.
            std::cerr << "[Logger] rotate failed: " << e.what() << '\n';
            currentHour_.clear();
            if (ofs_.is_open())
            {
                ofs_.close();
            }
            
            return;
        }
    }
}

void Logger::init(const std::string& dir, int retentionDays)
{
    // Set desired configuration under lock
    {
        std::lock_guard<std::mutex> lock(mutex_);
        dir_ = dir;
        retentionDays_ = (retentionDays < 0) ? 0 : retentionDays;

        // Apply configuration immediately: ensure log file exists and purge old logs
        try { rotateIfNeeded(); } catch (...) { /* 무시 */ }
    }

    // Mark initialization as done so ensureInitialized() won't attempt its one-time block later
    try
    {
        std::call_once(initFlag_, []() { /* no-op; mark as initialized */ });
    }
    catch (...) { /* 무시: call_once shouldn't throw here */ }
}

void Logger::setRetentionDays(int days)
{
    std::lock_guard<std::mutex> lock(mutex_);
    retentionDays_ = (days < 0) ? 0 : days;
    // Allow purge to run immediately after retention policy change
    purgedOnce_.store(false, std::memory_order_release);
    purgeOldLogs();
}

void Logger::purgeOldLogs()     // 보존기간 지난 로그 파일 삭제
{
    // Ensure we run purge only once per process unless explicitly reset (e.g., when retention changes)
    bool expected = false;
    if (!purgedOnce_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return; // already purged once
    }

    if (retentionDays_ <= 0) return; // 0 or negative => 보존 비활성

    try
    {
        if (!std::filesystem::exists(dir_))
        { 
            return;
        }

        auto now = std::chrono::system_clock::now();
        auto threshold = now - std::chrono::hours(24 * static_cast<long long>(retentionDays_));

        // 디렉토리 내 파일 순회
        // 디렉토리 안의 항목들을 비재귀적으로 반환(하위 디렉토리는 탐색하지 않음) 
        // 로그 파일명 패턴: siplite_YYYYMMDD_HH.txt
        
        for (const auto& entry : std::filesystem::directory_iterator(dir_))
        {
            if (!entry.is_regular_file()) continue;
            auto path = entry.path();
            auto name = path.filename().string();

            // 파일명 패턴: siplite_YYYYMMDD_HH.txt
            if (name.rfind("siplite_", 0) != 0) continue;
            if (path.extension() != ".txt") continue;

            auto ftime = std::filesystem::last_write_time(path);
            // 파일시간을 system_clock으로 변환
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - decltype(ftime)::clock::now() + std::chrono::system_clock::now());

            if (sctp < threshold)
            {
                std::error_code ec;
                std::filesystem::remove(path, ec);
                (void)ec; // 오류는 무시
            }
        }
    }
    catch (const std::exception&)
    {
        // cleanup 중 오류는 무시
    }
}

void Logger::ensureInitialized()
{
    // Ensure directory setup and any one-time init run exactly once
    try
    {
        std::call_once(initFlag_, [this]() 
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (dir_.empty()) dir_ = "logs";
            try { std::filesystem::create_directories(dir_); } catch (...) { /* 무시 */ }
        });
    }
    catch (...) { /* 무시 */ }

    // Always check rotation under lock to handle hour rollovers on each log call
    std::lock_guard<std::mutex> lock(mutex_);
    try { rotateIfNeeded(); } catch (...) { /* 무시 */ }
}


void Logger::shutdown()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (ofs_.is_open())
    { 
        ofs_.close();
    }

    currentHour_.clear();
}

void Logger::info(const std::string& msg)
{
    std::string line = timeStamp() + " [INFO] " + msg + "\n";

    ensureInitialized();

    // logInternal handles locking and both console/file output
    logInternal(line, false);
} 

void Logger::error(const std::string& msg)
{
    std::string line = timeStamp() + " [ERROR] " + msg + "\n";

    ensureInitialized();

    // logInternal handles locking and both console/file output
    logInternal(line, true);
}

void Logger::logInternal(const std::string& line, bool isError)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Console output (INFO->stdout, ERROR->stderr)
    try 
    { 
        if (isError)
        { 
            std::cerr << line; 
        }
        else
        {
            std::cout << line; 
        }

    } catch (...) { /* 무시 */ }

    // File output when available
    if (ofs_.is_open())
    {
        try { ofs_ << line; ofs_.flush(); } catch (...) { /* 무시 */ }
    }
}
