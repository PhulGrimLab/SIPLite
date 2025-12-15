#include "UdpServer.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>

namespace {
    std::mutex g_logMutex;
    constexpr std::size_t RECV_BUFFER_SIZE = 2048;  // UDP 수신 버퍼 크기
    constexpr std::size_t MAX_LOG_DATA_LENGTH = 200; // 로그 출력 최대 길이
    
    // 스레드 안전한 에러 로깅 (perror 대체)
    void logError(const char* prefix) {
        int savedErrno = errno;  // errno를 즉시 캡처
        char buf[256];
        // strerror_r의 GNU 버전과 XSI 버전 모두 처리
        #if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
        if (strerror_r(savedErrno, buf, sizeof(buf)) == 0) {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cerr << prefix << ": " << buf << " (errno=" << savedErrno << ")\n";
        }
        #else
        char* result = strerror_r(savedErrno, buf, sizeof(buf));
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << prefix << ": " << result << " (errno=" << savedErrno << ")\n";
        #endif
    }
    
    // 로그 출력용 문자열 정화 (로그 인젝션 방지)
    std::string sanitizeLogData(const std::string& data, std::size_t maxLen = MAX_LOG_DATA_LENGTH) 
    {
        std::string result;
        result.reserve(std::min(data.size(), maxLen));
        
        for (std::size_t i = 0; i < data.size() && result.size() < maxLen; ++i)
        {
            char c = data[i];
            // 출력 가능한 ASCII + 일부 공백 문자 허용
            if (c >= 32 && c < 127)
            {
                result += c;
            }
            else if (c == '\r' || c == '\n' || c == '\t')
            {
                result += c;  // SIP 메시지 구조 유지
            }
            else
            {
                result += '.';  // 비출력 문자는 .으로 대체
            }
        }
        
        if (data.size() > maxLen)
        {
            result += "... (truncated)";
        }
        
        return result;
    }
}

// sock_ = -1 일 때 소켓 닫힌 상태, running_ = false 일 때 서버 중지 상태
UdpServer::UdpServer()
    : sock_(-1), running_(false) {}

UdpServer::~UdpServer() 
{
    stop();
}

bool UdpServer::start(const std::string& ip, uint16_t port, std::size_t workerCount) 
{
    // 이미 실행 중인지 확인
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) 
    {
        std::cerr << "[UdpServer] Already running\n";
        return false;
    }

    // 이전 shutdown 상태 초기화 (재시작 지원)
    queue_.reset();

    if (!bindSocket(ip, port)) 
    {
        running_ = false;  // 실패 시 플래그 복원
        return false;
    }

    // 수신 스레드
    recvThread_ = std::thread(&UdpServer::recvLoop, this);

    // 워커 스레드들
    for (std::size_t i = 0; i < workerCount; ++i) 
    {
        workerThreads_.emplace_back(&UdpServer::workerLoop, this, i);
    }

    std::cout << "[UdpServer] started at " << ip << ":" << port
              << " with " << workerCount << " workers\n";
    return true;
}

void UdpServer::stop() 
{
    // Race condition 방지: atomic compare_exchange 사용
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) 
    {
        return;  // 이미 중지됨
    }

    // 워커에게 shutdown 알림
    queue_.shutdown();

    // 수신 스레드 깨우기 위해 소켓 닫기 (double-close 방지)
    int sock = sock_.exchange(-1);
    if (sock >= 0)
    {
        ::close(sock);
    }

    if (recvThread_.joinable()) 
    {
        recvThread_.join();
    }

    for (auto& th : workerThreads_) 
    {
        if (th.joinable()) 
        {
            th.join();
        }
    }
    
    workerThreads_.clear();

    std::cout << "[UdpServer] stopped\n";
}

bool UdpServer::bindSocket(const std::string& ip, uint16_t port) 
{
    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_ < 0) 
    {
        logError("socket");
        return false;
    }

    int reuse = 1;
    if (::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) 
    {
        logError("setsockopt(SO_REUSEADDR)");
    }

    // 수신 버퍼 크게 (예: 4MB)
    int rcvbuf = 4 * 1024 * 1024;
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) 
    {
        logError("setsockopt(SO_RCVBUF)");
    }

    // 수신 타임아웃 설정 (500ms) - 종료 시 recvfrom 블로킹 해제용
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  // 500ms
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) 
    {
        logError("setsockopt(SO_RCVTIMEO)");
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    
    // inet_pton 사용 (inet_addr보다 안전 - 오류 처리 가능)
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << "[UdpServer] Invalid bind IP address: " << ip << "\n";
        int sock = sock_.exchange(-1);
        if (sock >= 0)
        {
            ::close(sock);
        }
        return false;
    }

    if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) 
    {
        logError("bind");
        int sock = sock_.exchange(-1);
        if (sock >= 0) 
        {
            ::close(sock);
        }
        return false;
    }

    std::cout << "[UdpServer] bind " << ip << ":" << port << " 성공\n";
    return true;
}

void UdpServer::recvLoop() 
{
    std::cout << "[RecvLoop] started\n";

    while (running_) 
    {
        // 소켓 유효성 검사
        int currentSock = sock_.load();
        if (currentSock < 0) break;

        char buf[RECV_BUFFER_SIZE];
        sockaddr_in src;        // 송신자 주소 저장용
        socklen_t srclen = sizeof(src);
        std::memset(&src, 0, sizeof(src));

        ssize_t n = ::recvfrom(currentSock, buf, sizeof(buf) - 1, 0,
                               reinterpret_cast<sockaddr*>(&src), &srclen);
        if (n < 0) 
        {
            if (!running_) break;  // stop 과정에서 소켓 닫힌 경우
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 타임아웃 - running_ 체크 후 계속
                continue;
            }
            logError("recvfrom");
            continue;
        }

        buf[n] = '\0';

        // inet_ntop 사용 (thread-safe)
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, ipStr, sizeof(ipStr));

        UdpPacket pkt;
        pkt.remoteIp   = ipStr;
        pkt.remotePort = ntohs(src.sin_port);
        pkt.data.assign(buf, static_cast<std::size_t>(n));

        // 큐에 넣기 (move semantics 사용)
        if (!queue_.push(std::move(pkt)))
        {
            // 큐가 가득 찼거나 shutdown 상태 - 패킷 버림
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cerr << "[RecvLoop] Queue full or shutdown, packet dropped from "
                      << ipStr << ":" << ntohs(src.sin_port) << "\n";
        }
    }

    std::cout << "[RecvLoop] ended\n";
}

void UdpServer::workerLoop(std::size_t workerId) 
{
    std::cout << "[Worker " << workerId << "] started\n";

    while (true) 
    {
        UdpPacket pkt;
        if (!queue_.pop(pkt)) 
        {
            // shutdown + empty
            break;
        }

        handlePacket(workerId, pkt);
    }

    std::cout << "[Worker " << workerId << "] ended\n";
}

void UdpServer::handlePacket(std::size_t workerId, const UdpPacket& pkt) 
{
    // 패킷 크기 검증 (최소 SIP 메시지 크기: "SIP/2.0 200 OK\r\n\r\n" ≈ 20 바이트)
    constexpr std::size_t MIN_SIP_SIZE = 20;
    constexpr std::size_t MAX_SIP_SIZE = 65536;  // 64KB
    
    if (pkt.data.size() < MIN_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << "[Worker " << workerId << "] Packet too small from "
                  << pkt.remoteIp << ":" << pkt.remotePort 
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }
    
    if (pkt.data.size() > MAX_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << "[Worker " << workerId << "] Packet too large from "
                  << pkt.remoteIp << ":" << pkt.remotePort 
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }
    
    // 수신 로그 (정화된 데이터)
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cout << "------------------------------------------\n";
        std::cout << "[Worker " << workerId << "] from "
                << pkt.remoteIp << ":" << pkt.remotePort << "\n";
        std::cout << sanitizeLogData(pkt.data) << "\n";
    }

    // SIP 메시지 파싱
    SipMessage msg;
    if (!parseSipMessage(pkt.data, msg))
    {
        // SIP 메시지가 아니면 에코 모드
        if (sendTo(pkt.remoteIp, pkt.remotePort, pkt.data)) 
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cout << "[Worker " << workerId << "] Echo sent to "
                      << pkt.remoteIp << ":" << pkt.remotePort << "\n";
        }
        return;
    }

    // SIP 요청 처리
    std::string response;
    if (sipCore_.handlePacket(pkt, msg, response))
    {
        if (!response.empty())
        {
            // 응답 전송
            if (sendTo(pkt.remoteIp, pkt.remotePort, response)) 
            {
                std::lock_guard<std::mutex> lock(g_logMutex);
                std::cout << "[Worker " << workerId << "] SIP response sent to "
                          << pkt.remoteIp << ":" << pkt.remotePort << "\n";
                std::cout << sanitizeLogData(response) << "\n";
            } 
            else 
            {
                std::lock_guard<std::mutex> lock(g_logMutex);
                std::cerr << "[Worker " << workerId << "] Failed to send SIP response\n";
            }
        }
        else
        {
            // ACK 등 응답이 없는 요청
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cout << "[Worker " << workerId << "] SIP " << msg.method 
                      << " processed (no response)\n";
        }
    }
    else
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << "[Worker " << workerId << "] Failed to handle SIP message\n";
    }
}

bool UdpServer::sendTo(const std::string& ip, uint16_t port, const std::string& data) 
{
    int currentSock = sock_.load();
    if (currentSock < 0) 
    {
        return false;  // 소켓이 닫힌 상태
    }

    sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(port);
    
    if (inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) <= 0) 
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cerr << "[UdpServer] Invalid IP address: " << ip << "\n";
        return false;
    }

    ssize_t sent = ::sendto(currentSock, data.data(), data.size(), 0,
                         reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    if (sent < 0) 
    {
        logError("sendto");
        return false;
    }

    return static_cast<std::size_t>(sent) == data.size();
}
