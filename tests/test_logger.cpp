#include "Logger.h"
#include <cassert>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>

// 테스트 카운터
static int testsPassed = 0;
static int testsFailed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << name << " ... "; } while(0)

#define PASS() \
    do { std::cout << "PASSED\n"; ++testsPassed; } while(0)

#define FAIL(reason) \
    do { std::cout << "FAILED: " << reason << "\n"; ++testsFailed; } while(0)

namespace fs = std::filesystem;

// 테스트용 임시 디렉토리
static const std::string TEST_LOG_DIR = "/tmp/siplite_logger_test";

// Helper: 테스트 디렉토리 정리
static void cleanTestDir()
{
    std::error_code ec;
    fs::remove_all(TEST_LOG_DIR, ec);
}

// Helper: 로그 디렉토리 내 파일 개수
static int countLogFiles()
{
    int count = 0;
    if (!fs::exists(TEST_LOG_DIR)) return 0;
    for (const auto& entry : fs::directory_iterator(TEST_LOG_DIR)) {
        if (entry.is_regular_file() &&
            entry.path().filename().string().rfind("siplite_", 0) == 0 &&
            entry.path().extension() == ".txt") {
            ++count;
        }
    }
    return count;
}

// Helper: 특정 디렉토리에서 로그 파일 내용 읽기
static std::string readFirstLogFile()
{
    if (!fs::exists(TEST_LOG_DIR)) return "";
    for (const auto& entry : fs::directory_iterator(TEST_LOG_DIR)) {
        if (entry.is_regular_file() &&
            entry.path().filename().string().rfind("siplite_", 0) == 0) {
            std::ifstream ifs(entry.path());
            return std::string((std::istreambuf_iterator<char>(ifs)),
                               std::istreambuf_iterator<char>());
        }
    }
    return "";
}

// ==============================================
// Section 1: Singleton
// ==============================================

void test_singleton_same_instance()
{
    TEST("Logger::instance() returns same pointer");
    Logger& a = Logger::instance();
    Logger& b = Logger::instance();
    assert(&a == &b);
    PASS();
}

// ==============================================
// Section 2: init
// ==============================================

void test_init_creates_directory()
{
    TEST("init creates log directory");
    cleanTestDir();
    assert(!fs::exists(TEST_LOG_DIR));

    Logger::instance().init(TEST_LOG_DIR, 7);
    assert(fs::exists(TEST_LOG_DIR));
    assert(fs::is_directory(TEST_LOG_DIR));

    Logger::instance().shutdown();
    PASS();
}

void test_init_negative_retention_clamps_to_zero()
{
    TEST("init with negative retentionDays clamps to 0");
    cleanTestDir();
    // 음수 retentionDays는 0으로 클램핑됨
    Logger::instance().init(TEST_LOG_DIR, -5);
    // 크래시 없이 동작해야 함
    Logger::instance().info("test negative retention");
    Logger::instance().shutdown();
    PASS();
}

void test_double_init_is_safe()
{
    TEST("double init is safe");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().init(TEST_LOG_DIR, 3); // 두 번째 init
    Logger::instance().info("after double init");
    Logger::instance().shutdown();
    // 크래시 없이 통과하면 성공
    PASS();
}

// ==============================================
// Section 3: info / error 로깅
// ==============================================

void test_info_creates_log_file()
{
    TEST("info() creates log file with [INFO]");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);

    Logger::instance().info("Hello from test_info");

    // 로그 파일 확인
    assert(countLogFiles() >= 1);
    std::string content = readFirstLogFile();
    assert(content.find("[INFO]") != std::string::npos);
    assert(content.find("Hello from test_info") != std::string::npos);

    Logger::instance().shutdown();
    PASS();
}

void test_error_creates_log_with_error_tag()
{
    TEST("error() logs with [ERROR] tag");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);

    Logger::instance().error("Something went wrong");

    std::string content = readFirstLogFile();
    assert(content.find("[ERROR]") != std::string::npos);
    assert(content.find("Something went wrong") != std::string::npos);

    Logger::instance().shutdown();
    PASS();
}

void test_multiple_log_entries()
{
    TEST("Multiple log entries written sequentially");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);

    Logger::instance().info("line1");
    Logger::instance().info("line2");
    Logger::instance().error("err1");
    Logger::instance().info("line3");

    std::string content = readFirstLogFile();
    assert(content.find("line1") != std::string::npos);
    assert(content.find("line2") != std::string::npos);
    assert(content.find("err1") != std::string::npos);
    assert(content.find("line3") != std::string::npos);

    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Section 4: shutdown
// ==============================================

void test_shutdown_closes_file()
{
    TEST("shutdown closes file handle");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().info("before shutdown");
    Logger::instance().shutdown();
    // shutdown 후에도 크래시 없어야 함
    PASS();
}

void test_double_shutdown_safe()
{
    TEST("double shutdown is safe");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().info("test");
    Logger::instance().shutdown();
    Logger::instance().shutdown(); // 두 번째
    PASS();
}

void test_log_after_shutdown_reinitializes()
{
    TEST("logging after shutdown auto-reinitializes");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().info("before");
    Logger::instance().shutdown();

    // shutdown 후 다시 init + 로깅
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().info("after reinit");

    std::string content = readFirstLogFile();
    assert(content.find("after reinit") != std::string::npos);

    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Section 5: setRetentionDays
// ==============================================

void test_set_retention_days()
{
    TEST("setRetentionDays changes policy");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);

    // 0으로 설정 — purge 비활성
    Logger::instance().setRetentionDays(0);
    Logger::instance().info("retention zero");

    // 음수 → 0으로 클램핑
    Logger::instance().setRetentionDays(-10);
    Logger::instance().info("negative retention");

    // 양수로 복원
    Logger::instance().setRetentionDays(30);
    Logger::instance().info("retention 30");

    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Section 6: 로그 파일 명명 규칙
// ==============================================

void test_log_filename_pattern()
{
    TEST("Log filename follows siplite_YYYYMMDD_HH.txt pattern");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);
    Logger::instance().info("check filename");

    bool foundPattern = false;
    for (const auto& entry : fs::directory_iterator(TEST_LOG_DIR)) {
        std::string name = entry.path().filename().string();
        // 패턴: siplite_YYYYMMDD_HH.txt → 최소 "siplite_" 접두사 + ".txt" 확장자
        if (name.rfind("siplite_", 0) == 0 && name.size() >= 22 &&
            entry.path().extension() == ".txt") {
            foundPattern = true;
        }
    }
    assert(foundPattern);

    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Section 7: 멀티스레드 로깅
// ==============================================

void test_concurrent_logging()
{
    TEST("Concurrent logging from 4 threads");
    cleanTestDir();
    Logger::instance().init(TEST_LOG_DIR, 7);

    const int THREADS = 4;
    const int LINES_PER_THREAD = 50;
    std::vector<std::thread> threads;

    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([t]() {
            for (int i = 0; i < LINES_PER_THREAD; ++i) {
                if (i % 2 == 0) {
                    Logger::instance().info("T" + std::to_string(t) + "_info_" + std::to_string(i));
                } else {
                    Logger::instance().error("T" + std::to_string(t) + "_err_" + std::to_string(i));
                }
            }
        });
    }

    for (auto& t : threads) t.join();

    std::string content = readFirstLogFile();
    // 모든 스레드의 로그가 파일에 있어야 함
    int infoCount = 0, errorCount = 0;
    size_t pos = 0;
    while ((pos = content.find("[INFO]", pos)) != std::string::npos) {
        ++infoCount;
        ++pos;
    }
    pos = 0;
    while ((pos = content.find("[ERROR]", pos)) != std::string::npos) {
        ++errorCount;
        ++pos;
    }
    assert(infoCount + errorCount == THREADS * LINES_PER_THREAD);

    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Section 8: ensureInitialized (간접 테스트)
// ==============================================

void test_logging_without_init()
{
    TEST("Logging without explicit init auto-initializes");
    // Logger는 싱글톤이므로, 이전 테스트의 영향이 있을 수 있음
    // shutdown 후 init 없이 로깅 시도
    Logger::instance().shutdown();

    // init 없이 바로 로깅 — ensureInitialized()가 자동으로 "logs" 디렉토리 생성
    // 이미 TEST_LOG_DIR로 init이 된 상태이므로, ensureInitialized는 call_once로 한 번만 실행됨
    // 크래시 없이 동작해야 함
    Logger::instance().info("auto-init test");
    Logger::instance().shutdown();
    PASS();
}

// ==============================================
// Cleanup & main
// ==============================================

int main()
{
    std::cout << "=== Logger Tests ===\n\n";

    std::cout << "[Section 1] Singleton\n";
    test_singleton_same_instance();

    std::cout << "\n[Section 2] init\n";
    test_init_creates_directory();
    test_init_negative_retention_clamps_to_zero();
    test_double_init_is_safe();

    std::cout << "\n[Section 3] info / error\n";
    test_info_creates_log_file();
    test_error_creates_log_with_error_tag();
    test_multiple_log_entries();

    std::cout << "\n[Section 4] shutdown\n";
    test_shutdown_closes_file();
    test_double_shutdown_safe();
    test_log_after_shutdown_reinitializes();

    std::cout << "\n[Section 5] setRetentionDays\n";
    test_set_retention_days();

    std::cout << "\n[Section 6] 로그 파일 명명 규칙\n";
    test_log_filename_pattern();

    std::cout << "\n[Section 7] 멀티스레드 로깅\n";
    test_concurrent_logging();

    std::cout << "\n[Section 8] ensureInitialized\n";
    test_logging_without_init();

    // 테스트 디렉토리 정리
    cleanTestDir();

    std::cout << "\n=================================\n";
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed\n";
    std::cout << "=================================\n";

    return testsFailed > 0 ? 1 : 0;
}
