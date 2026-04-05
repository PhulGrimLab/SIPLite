#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <cstddef>

class Logger
{
public:
    static Logger& instance();

    // 로그 디렉토리(기본 "logs") 및 보존기간(일, 기본 7일)을 지정하여 초기화
    void init(const std::string& dir = "logs", int retentionDays = 7);

    // 런타임에 보존기간(일 단위) 변경 (0이면 보존 안함)
    void setRetentionDays(int days);

    void info(const std::string& msg);
    void error(const std::string& msg);
    void shutdown();

private:
    Logger();
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void rotateIfNeeded();
    void purgeOldLogs();
    void loadFlushPolicy();

    // Ensure logger is initialized exactly once using std::call_once
    void ensureInitialized();
    void logInternal(const std::string& line, bool isError);

    std::string dir_;
    std::string currentHour_;
    std::ofstream ofs_;
    std::mutex mutex_;
    int retentionDays_ = 7; // 보존기간(일)
    std::size_t flushEvery_ = 16;
    std::size_t pendingFlushCount_ = 0;
    std::once_flag initFlag_;
    std::atomic<bool> purgedOnce_{false}; // ensure purge runs at most once per process, unless forced
};
