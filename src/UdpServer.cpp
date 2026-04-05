#include "UdpServer.h"
#include "SipUtils.h"
#include "Logger.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <functional>

// static 변수 대신에 namespace 사용
namespace
{
    std::mutex g_logMutex;

    /*
    constexpr : 반드시 컴파일 타임에 값이 결정되어야 한다.
    const : 런타임에 결정될 수 있지만, 변경되지 않는 값을 나타낸다.

    constexpr 장점
    1. 배열크기, 템플릿 인자 등의 컴파일 타임 상수가 필요한 곳에 사용가능
    2. 컴파일러 최적화에 유리 (컴파일러가 값을 미리 알고 있음)
    3. 타입 안전한 매크로 대체 (#define 대신 사용)
    */

    constexpr std::size_t RECV_BUFFER_SIZE = 65536; // UDP 수신 버퍼 크기 (최대 SIP 메시지 크기)
    constexpr std::size_t MAX_LOG_DATA_LENGTH = 200; // 로그 출력 최대 길이

    // 전체 SIP 파싱 없이 Call-ID만 빠르게 추출
    // recvLoop에서 워커 라우팅 시 사용 — 전체 파싱보다 훨씬 가벼움
    std::string extractCallIdQuickImpl(const std::string& data)
    {
        // "Call-ID:", "call-id:", "Call-Id:", "i:" (compact form) 검색
        static const char* patterns[] = {
            "\r\nCall-ID:", "\r\ncall-id:", "\r\nCall-Id:",
            "\r\ni:", nullptr
        };

        for (const char** p = patterns; *p; ++p)
        {
            auto pos = data.find(*p);
            if (pos != std::string::npos)
            {
                pos += std::strlen(*p);
                // 공백 건너뛰기
                while (pos < data.size() && data[pos] == ' ') ++pos;

                // \r\n까지 추출
                auto end = data.find("\r\n", pos);
                if (end == std::string::npos) end = data.size();

                std::string callId = data.substr(pos, end - pos);
                // 후행 공백 제거
                while (!callId.empty() && callId.back() == ' ') callId.pop_back();
                return callId;
            }
        }
        return {};
    }

    // 스레드 안전한 로그 에러 로깅 (perror 대체)
    void logError(const char* prefix)
    {
        int savedErrno = errno; // errno 값을 저장
        char buf[256];
        std::string s;
        // strerror_r의 GNU 버전과 XSI 버전 모두 처리
        #if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
        if (strerror_r(savedErrno, buf, sizeof(buf)) == 0) {
            s = std::string(prefix) + ": " + buf + " (errno=" + std::to_string(savedErrno) + ")";
        } else {
            s = std::string(prefix) + ": errno=" + std::to_string(savedErrno);
        }
        #else
        char* result = strerror_r(savedErrno, buf, sizeof(buf));
        s = std::string(prefix) + ": " + result + " (errno=" + std::to_string(savedErrno) + ")";
        #endif

        Logger::instance().error(s);
    }
}

// sock_ = -1 일 때 소켓 닫힌 상태, running_ = false 일 때 서버 중지 상태
UdpServer::UdpServer()
    : sock_(-1), running_(false) {}

UdpServer::~UdpServer()
{
    stop();
}

// Call-ID에서 워커 인덱스 결정 (해시 기반 — 같은 Call-ID는 항상 같은 워커로)
std::size_t UdpServer::routeToWorker(const std::string& callId) const
{
    if (workerCount_ == 0) return 0;
    std::size_t hash = std::hash<std::string>{}(callId);
    return hash % workerCount_;
}

// static wrapper
std::string UdpServer::extractCallIdQuick(const std::string& data)
{
    return extractCallIdQuickImpl(data);
}

bool UdpServer::start(const std::string& ip, uint16_t port, std::size_t workerCount)
{
    // 이미 실행 중인지 확인
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) // 원자적 연산
    {
        std::cerr << "[UdpServer] Already running\n";
        return false;
    }

    workerCount_ = workerCount;

    // 워커별 전용 큐 생성 (이전 상태 초기화 포함)
    workerQueues_.clear();
    workerQueues_.reserve(workerCount);
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerQueues_.push_back(std::make_unique<ConcurrentQueue<UdpPacket>>());
    }

    if (!bindSocket(ip, port))
    {
        running_.store(false); // 실패 시 상태 복구
        return false;
    }

    // SIP 코어에 송신 콜백 설정
    sipCore_.setSender([this](const std::string& ip, uint16_t port, const std::string& data, TransportType){
        return this->sendTo(ip, port, data);
    });

    // 프록시 로컬 주소 설정 (Via 헤더 생성용)
    // "0.0.0.0" 바인딩인 경우 실제 로컬 IP를 감지
    std::string localIp = ip;
    if (ip == "0.0.0.0")
    {
        int tmpSock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (tmpSock >= 0)
        {
            struct sockaddr_in target{};
            target.sin_family = AF_INET;
            target.sin_port = htons(53);
            ::inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
            if (::connect(tmpSock, reinterpret_cast<struct sockaddr*>(&target), sizeof(target)) == 0)
            {
                struct sockaddr_in local{};
                socklen_t len = sizeof(local);
                if (::getsockname(tmpSock, reinterpret_cast<struct sockaddr*>(&local), &len) == 0)
                {
                    char buf[INET_ADDRSTRLEN];
                    if (::inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf)))
                    {
                        localIp = buf;
                    }
                }
            }
            ::close(tmpSock);
        }
    }
    sipCore_.setLocalAddress(localIp, port);
    sipCore_.setLocalAddressForTransport(TransportType::UDP, localIp, port);
    sipCore_.setLocalAddressForTransport(TransportType::TCP, localIp, port);
    Logger::instance().info("[UdpServer] Proxy local address: " + localIp + ":" + std::to_string(port));

    // 수신 스레드 시작
    recvThread_ = std::thread(&UdpServer::recvLoop, this);

    // 워커 스레드 시작
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerThreads_.emplace_back(&UdpServer::workerLoop, this, i);
    }

    Logger::instance().info(std::string("[UdpServer] started at ") + ip + ":" + std::to_string(port) + " with " + std::to_string(workerCount) + " workers (call-affinity routing)");
    return true;
}

void UdpServer::stop()
{
    // Race condition 방지: atomic compare_exchange_strong 사용
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) // 원자적 연산
    {
        return; // 이미 중지 상태
    }

    // 모든 워커 큐 종료 알림
    for (auto& q : workerQueues_)
    {
        q->shutdown();
    }

    // 수신 스레드 깨우기 위해 소켓 닫기 (double-close 방지)
    int sock = sock_.exchange(-1);
    if (sock >= 0)
    {
        ::close(sock);
    }

    // 수신 스레드 종료 대기
    if (recvThread_.joinable())
    {
        recvThread_.join();
    }

    // 워커 스레드 종료 대기
    for (auto& thread : workerThreads_)
    {
        if (thread.joinable())
        {
            thread.join();
        }
    }

    workerThreads_.clear();
    workerQueues_.clear();
    workerCount_ = 0;

    Logger::instance().info("[UdpServer] Stopped");
}

bool UdpServer::bindSocket(const std::string& ip, uint16_t port)
{
    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);   // UDP 소켓 생성, ::는 전역 네임스페이스 지정자

    if (sock_ < 0)
    {
        logError("socket");
        return false;
    }

    int reuse = 1;  // 재사용 옵션 활성화 1, 비활성화 0
    // 주소 재사용 옵션 설정
    // 위에 소켓 생성할때 전역 네임스페이스에 있는것을 사용한다고 명시했기 때문에 ::setsockopt 사용
    if (::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        logError("setsockopt(SO_REUSEADDR)");
    }

    // 수신 버퍼 크기 설정 (4MB)
    int rcvbuf = 4*1024*1024;
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
    {
        logError("setsockopt(SO_RCVBUF)");
    }

    // 수신 타임아웃 설정 (500ms) - 종료 시 recvfrom 블로킹 해제용
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500 * 1000; // 500 milliseconds
    if (::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        logError("setsockopt(SO_RCVTIMEO)");
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // inet_pton: IP 주소 문자열을 바이너리 형태로 변환
    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        Logger::instance().error(std::string("[UdpServer] Invalid IP address: ") + ip);
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

    Logger::instance().info(std::string("[UdpServer] bind ") + ip + ":" + std::to_string(port) + " 성공");
    return true;
}

void UdpServer::recvLoop()
{
    Logger::instance().info("[UdpServer] recvLoop started");

    while (running_)
    {
        // 소켓 유효성 검사
        int currentSock = sock_.load();
        if (currentSock < 0)
        {
            break; // 소켓이 닫혔으므로 종료
        }

        char buf[RECV_BUFFER_SIZE];
        sockaddr_in src;        // 송신자 주소 저장용
        socklen_t srclen = sizeof(src);
        std::memset(&src, 0, sizeof(src));

        ssize_t n = ::recvfrom(currentSock, buf, sizeof(buf) - 1, 0,
                                     reinterpret_cast<sockaddr*>(&src), &srclen);

        if (n < 0)
        {
            if (!running_)
            {
                break; // 서버 중지 상태이면 종료
            }

            // 타임아웃 또는 인터럽트 시 계속
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }

            // Socket closed during shutdown — exit cleanly
            if (errno == EBADF)
            {
                break;
            }

            logError("recvfrom");
            continue;
        }

        buf[n] = '\0';

        // inet_ntop: 바이너리 IP 주소를 문자열로 변환
        char ipStr[INET_ADDRSTRLEN];
        ::inet_ntop(AF_INET, &src.sin_addr, ipStr, sizeof(ipStr));

        UdpPacket pkt;
        pkt.remoteIp = ipStr;
        pkt.remotePort = ntohs(src.sin_port);
        pkt.data.assign(buf, static_cast<std::size_t>(n));

        // Call-ID 기반으로 워커 라우팅 (같은 통화의 모든 패킷은 항상 같은 워커에서 순서대로 처리)
        std::string callId = extractCallIdQuick(pkt.data);
        std::size_t workerIdx = callId.empty() ? 0 : routeToWorker(callId);

        if (!workerQueues_[workerIdx]->push(std::move(pkt)))
        {
            Logger::instance().error(std::string("[UdpServer] Warning: Worker queue[") + std::to_string(workerIdx)
                      + "] full or shutting down, dropping packet from "
                      + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
        }
    }

    Logger::instance().info("[UdpServer] recvLoop ended");
}

void UdpServer::workerLoop(std::size_t workerId)
{
    Logger::instance().info(std::string("[UdpServer] Worker ") + std::to_string(workerId) + " started");

    while (true)
    {
        UdpPacket pkt;
        if (!workerQueues_[workerId]->pop(pkt))
        {
            break; // 큐가 비어있거나 종료 상태
        }

        handlePacket(workerId, pkt);
    }

    // Periodic cleanup of stale transactions
    try
    {
        std::size_t removed = sipCore_.cleanupStaleTransactions();

        if (removed > 0)
        {
            std::lock_guard<std::mutex> lock(g_logMutex);  
            std::cout << "[UdpServer] cleanupStaleTransactions removed " << removed << " entries\n";
        }
    }
    catch(...)
    {
        // be defensive: cleanup must not throw
    }

    Logger::instance().info(std::string("[UdpServer] Worker ") + std::to_string(workerId) + " ended");
}

// 실제 패킷 처리 로직
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

    if (isVerboseSipLoggingEnabled())
    {
        std::lock_guard<std::mutex> lock(g_logMutex);
        std::cout << "------------------------------------------\n";
        std::cout << "[Worker " << workerId << "] from "
                << pkt.remoteIp << ":" << pkt.remotePort << "\n";
        std::cout << sanitizeSipForLog(pkt.data, MAX_LOG_DATA_LENGTH) << "\n";
    }

    // SIP 메시지 파싱
    SipMessage msg;
    if (!parseSipMessage(pkt.data, msg))
    {
        // 파싱 실패: 잘못된 패킷은 보안상 drop (에코 금지)
        std::lock_guard<std::mutex> lock(g_logMutex);
        Logger::instance().info("[Worker " + std::to_string(workerId)
            + "] Malformed SIP message dropped from "
            + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
        return;
    }

    std::string response;
    if (msg.type == SipType::Request)
    {
        if (sipCore_.handlePacket(pkt, msg, response))
        {
            if (!response.empty())
            {
                // 응답 전송
                if (sendTo(pkt.remoteIp, pkt.remotePort, response))
                {
                    if (isVerboseSipLoggingEnabled())
                    {
                        std::lock_guard<std::mutex> lock(g_logMutex);
                        std::cout << "[Worker " << workerId << "] SIP response sent to "
                                  << pkt.remoteIp << ":" << pkt.remotePort << "\n";
                        std::cout << sanitizeSipForLog(response, MAX_LOG_DATA_LENGTH) << "\n";
                    }
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
            std::cerr << "[Worker " << workerId << "] Failed to handle SIP request\n";
        }
    }
    else
    {
        // Response 메시지: 이전에 포워딩한 INVITE의 응답일 수 있으므로 SipCore에 전달
        if (sipCore_.handleResponse(pkt, msg))
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cout << "[Worker " << workerId << "] Forwarded SIP response for Call-ID "
                      << sanitizeForDisplay(getHeader(msg, "call-id"), MAX_LOG_DATA_LENGTH) << "\n";
        }
        else
        {
            std::lock_guard<std::mutex> lock(g_logMutex);
            std::cerr << "[Worker " << workerId << "] Unhandled SIP response\n";
        }
    }
    
}

bool UdpServer::sendTo(const std::string& ip, uint16_t port, const std::string& data)
{
    int currentSock = sock_.load();
    if (currentSock < 0) 
    {
        return false; // 소켓이 닫혔음
    }

    sockaddr_in dest;       // 목적지 주소 구조체
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);

    if (::inet_pton(AF_INET, ip.c_str(), &dest.sin_addr) <= 0)  // IP 문자열 -> 바이너리 변환
    {
        Logger::instance().error(std::string("[UdpServer] sendTo Invalid IP address: ") + ip);
        return false;
    }

    ssize_t n = ::sendto(currentSock, data.data(), data.size(), 0,
                         reinterpret_cast<sockaddr*>(&dest), sizeof(dest));

    /*

    reinterpret_cast 의미 🔧
    **reinterpret_cast**는 C++에서 비트 레벨로 타입을 재해석(reinterpret)할 때 쓰는 최하위(저수준) 캐스트입니다.
    런타임 검사나 변환을 하지 않고, 단순히 그 메모리의 비트 패턴을 다른 타입으로 "다르게 본다"는 뜻입니다.
    주로 쓰이는 경우 ✅
    서로 관련 없는 포인터 타입 간 변환 (예: sockaddr_in* → sockaddr*)
    포인터 ↔ 정수 타입 변환 (구현 정의/주의 필요)
    하드웨어/저수준 API 호출에 맞추는 경우

    sockaddr_in dest;
    // C 소켓 API는 sockaddr* 를 요구하므로 재해석해서 전달
    ::bind(sock, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    */

    if (n < 0)
    {
        logError("sendto");
        return false;
    }

    return static_cast<std::size_t>(n) == data.size();
}
