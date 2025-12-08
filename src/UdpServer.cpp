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
    if (!bindSocket(ip, port)) 
    {
        return false;
    }

    running_ = true;

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
        perror("socket");
        return false;
    }

    int reuse = 1;
    if (::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) 
    {
        perror("setsockopt(SO_REUSEADDR)");
    }

    // 수신 버퍼 크게 (예: 4MB)
    int rcvbuf = 4 * 1024 * 1024;
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) 
    {
        perror("setsockopt(SO_RCVBUF)");
    }

    // 수신 타임아웃 설정 (500ms) - 종료 시 recvfrom 블로킹 해제용
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;  // 500ms
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) 
    {
        perror("setsockopt(SO_RCVTIMEO)");
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) 
    {
        perror("bind");
        ::close(sock_);
        sock_ = -1;
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
            perror("recvfrom");
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
        queue_.push(std::move(pkt));
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
    // 로그 출력 시 mutex 보호 (스레드 간 출력 섞임 방지)
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::cout << "------------------------------------------\n";
    std::cout << "[Worker " << workerId << "] from "
              << pkt.remoteIp << ":" << pkt.remotePort << "\n";
    std::cout << pkt.data << "\n";

    // 나중에 여기서:
    //  - SIP 파서 붙이고
    //  - REGISTER/INVITE 처리로 넘기면 됨
}
