#include "TcpServer.h"
#include "SipUtils.h"
#include "Logger.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <functional>

namespace
{
    std::mutex g_tcpLogMutex;
    constexpr std::size_t MAX_LOG_DATA_LENGTH = 200;

    // 스레드 안전한 에러 로깅
    void logError(const char* prefix)
    {
        int savedErrno = errno;
        char buf[256];
        std::string s;
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

    // 소켓을 논블로킹으로 설정
    bool setNonBlocking(int fd)
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0) return false;
        return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
    }

    // Call-ID 빠른 추출 (UdpServer와 동일한 로직)
    std::string extractCallIdQuickImpl(const std::string& data)
    {
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
                while (pos < data.size() && data[pos] == ' ') ++pos;
                auto end = data.find("\r\n", pos);
                if (end == std::string::npos) end = data.size();
                std::string callId = data.substr(pos, end - pos);
                while (!callId.empty() && callId.back() == ' ') callId.pop_back();
                return callId;
            }
        }
        return {};
    }
}

TcpServer::TcpServer(SipCore& sipCore)
    : listenSock_(-1), running_(false), sipCore_(sipCore) {}

TcpServer::~TcpServer()
{
    stop();
}

std::size_t TcpServer::routeToWorker(const std::string& callId) const
{
    if (workerCount_ == 0) return 0;
    std::size_t hash = std::hash<std::string>{}(callId);
    return hash % workerCount_;
}

std::string TcpServer::extractCallIdQuick(const std::string& data)
{
    return extractCallIdQuickImpl(data);
}

std::size_t TcpServer::connectionCount() const
{
    std::lock_guard<std::mutex> lock(connMutex_);
    return connections_.size();
}

bool TcpServer::hasConnection(const std::string& ip, uint16_t port) const
{
    std::lock_guard<std::mutex> lock(connMutex_);
    for (const auto& [fd, conn] : connections_)
    {
        if (conn.remoteIp == ip && conn.remotePort == port)
            return true;
    }
    return false;
}

bool TcpServer::start(const std::string& ip, uint16_t port, std::size_t workerCount)
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true))
    {
        std::cerr << "[TcpServer] Already running\n";
        return false;
    }

    bindIp_ = ip;
    bindPort_ = port;
    workerCount_ = workerCount;

    // 워커별 전용 큐 생성
    workerQueues_.clear();
    workerQueues_.reserve(workerCount);
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerQueues_.push_back(std::make_unique<ConcurrentQueue<UdpPacket>>());
    }

    if (!bindSocket(ip, port))
    {
        running_.store(false);
        return false;
    }

    // epoll 인스턴스 생성
    epollFd_ = ::epoll_create1(0);
    if (epollFd_ < 0)
    {
        logError("epoll_create1");
        int sock = listenSock_.exchange(-1);
        if (sock >= 0) ::close(sock);
        running_.store(false);
        return false;
    }

    // 수신 루프 스레드 시작 (epoll 기반)
    recvThread_ = std::thread(&TcpServer::recvLoop, this);

    // 워커 스레드 시작
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerThreads_.emplace_back(&TcpServer::workerLoop, this, i);
    }

    Logger::instance().info(std::string("[TcpServer] started at ") + ip + ":" + std::to_string(port)
        + " with " + std::to_string(workerCount) + " workers");
    return true;
}

void TcpServer::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false))
    {
        return;
    }

    // 모든 워커 큐 종료 알림
    for (auto& q : workerQueues_)
    {
        q->shutdown();
    }

    // 리스닝 소켓 닫기
    int sock = listenSock_.exchange(-1);
    if (sock >= 0)
    {
        ::close(sock);
    }

    // epoll 닫기
    if (epollFd_ >= 0)
    {
        ::close(epollFd_);
        epollFd_ = -1;
    }

    // 모든 클라이언트 연결 닫기
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        for (auto& [fd, conn] : connections_)
        {
            ::close(fd);
        }
        connections_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        outgoingConns_.clear();
    }

    // 스레드 종료 대기
    if (recvThread_.joinable())
    {
        recvThread_.join();
    }

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

    Logger::instance().info("[TcpServer] Stopped");
}

bool TcpServer::bindSocket(const std::string& ip, uint16_t port)
{
    listenSock_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock_ < 0)
    {
        logError("socket(TCP)");
        return false;
    }

    // 주소 재사용 옵션
    int reuse = 1;
    if (::setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        logError("setsockopt(SO_REUSEADDR)");
    }

    // TCP_NODELAY (Nagle 알고리즘 비활성화 - SIP 메시지는 즉시 전송)
    int nodelay = 1;
    if (::setsockopt(listenSock_, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0)
    {
        logError("setsockopt(TCP_NODELAY)");
    }

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        Logger::instance().error(std::string("[TcpServer] Invalid IP address: ") + ip);
        int s = listenSock_.exchange(-1);
        if (s >= 0) ::close(s);
        return false;
    }

    if (::bind(listenSock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        logError("bind(TCP)");
        int s = listenSock_.exchange(-1);
        if (s >= 0) ::close(s);
        return false;
    }

    // 논블로킹 설정
    if (!setNonBlocking(listenSock_))
    {
        logError("fcntl(TCP listen)");
        int s = listenSock_.exchange(-1);
        if (s >= 0) ::close(s);
        return false;
    }

    // listen 시작 (백로그: 128)
    if (::listen(listenSock_, 128) < 0)
    {
        logError("listen");
        int s = listenSock_.exchange(-1);
        if (s >= 0) ::close(s);
        return false;
    }

    Logger::instance().info(std::string("[TcpServer] bind TCP ") + ip + ":" + std::to_string(port) + " 성공");
    return true;
}

void TcpServer::addConnection(int fd, const std::string& ip, uint16_t port)
{
    TcpConnection conn;
    conn.fd = fd;
    conn.remoteIp = ip;
    conn.remotePort = port;
    conn.lastActive = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(connMutex_);
        if (connections_.size() >= static_cast<std::size_t>(MAX_CONNECTIONS))
        {
            Logger::instance().error("[TcpServer] Max connections reached, rejecting " + ip + ":" + std::to_string(port));
            ::close(fd);
            return;
        }
        connections_[fd] = std::move(conn);
    }

    // epoll에 등록 (EPOLLIN | EPOLLET: Edge-triggered)
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;
    if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
        logError("epoll_ctl(ADD)");
        removeConnection(fd);
    }
}

void TcpServer::removeConnection(int fd)
{
    // epoll에서 제거
    ::epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);

    std::string key;
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        auto it = connections_.find(fd);
        if (it != connections_.end())
        {
            key = it->second.remoteIp + ":" + std::to_string(it->second.remotePort);
            Logger::instance().info("[TcpServer] Connection closed: " + key);
            connections_.erase(it);
        }
    }

    // 아웃바운드 매핑에서도 제거
    if (!key.empty())
    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        auto it = outgoingConns_.find(key);
        if (it != outgoingConns_.end() && it->second == fd)
        {
            outgoingConns_.erase(it);
        }
    }

    ::close(fd);
}

int TcpServer::findOrCreateConnection(const std::string& ip, uint16_t port)
{
    std::string key = ip + ":" + std::to_string(port);

    // 기존 연결 검색
    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        auto it = outgoingConns_.find(key);
        if (it != outgoingConns_.end())
        {
            // 연결이 아직 유효한지 확인
            std::lock_guard<std::mutex> lockConn(connMutex_);
            if (connections_.count(it->second))
            {
                return it->second;
            }
            // 유효하지 않으면 매핑 제거
            outgoingConns_.erase(it);
        }
    }

    // 인바운드 연결에서 같은 IP:Port 검색
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        for (const auto& [fd, conn] : connections_)
        {
            if (conn.remoteIp == ip && conn.remotePort == port)
            {
                // 아웃바운드 매핑에 등록
                std::lock_guard<std::mutex> lockOut(outConnMutex_);
                outgoingConns_[key] = fd;
                return fd;
            }
        }
    }

    // 새 아웃바운드 연결 생성
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        logError("socket(TCP outbound)");
        return -1;
    }

    // TCP_NODELAY 설정
    int nodelay = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0)
    {
        ::close(fd);
        return -1;
    }

    // 블로킹 connect (타임아웃 설정)
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        logError("connect(TCP outbound)");
        ::close(fd);
        return -1;
    }

    // 논블로킹으로 전환
    if (!setNonBlocking(fd))
    {
        ::close(fd);
        return -1;
    }

    // 연결 등록 (epoll + 관리 맵)
    addConnection(fd, ip, port);

    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        outgoingConns_[key] = fd;
    }

    Logger::instance().info("[TcpServer] Outbound connection to " + key);
    return fd;
}

// SIP 메시지 프레이밍: 버퍼에서 완전한 SIP 메시지 추출
// RFC 3261 §18.3: Content-Length 헤더 기반 프레이밍
bool TcpServer::extractSipMessage(std::string& buffer, std::string& message)
{
    // 헤더 끝 찾기 (\r\n\r\n)
    auto headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
        return false;  // 헤더가 아직 완전하지 않음
    }

    std::size_t bodyStart = headerEnd + 4;

    // Content-Length 헤더 파싱
    std::size_t contentLength = 0;
    static const char* clPatterns[] = {
        "\r\nContent-Length:", "\r\ncontent-length:", "\r\nContent-length:",
        "\r\nl:", nullptr  // compact form
    };

    std::string headers = buffer.substr(0, bodyStart);
    for (const char** p = clPatterns; *p; ++p)
    {
        auto pos = headers.find(*p);
        if (pos != std::string::npos)
        {
            pos += std::strlen(*p);
            while (pos < headers.size() && headers[pos] == ' ') ++pos;
            auto end = headers.find("\r\n", pos);
            if (end == std::string::npos) end = headers.size();
            std::string clStr = headers.substr(pos, end - pos);
            // 후행 공백 제거
            while (!clStr.empty() && clStr.back() == ' ') clStr.pop_back();
            try
            {
                contentLength = std::stoul(clStr);
            }
            catch (...)
            {
                contentLength = 0;
            }
            break;
        }
    }

    // Content-Length 보안 검증
    if (contentLength > MAX_SIP_SIZE)
    {
        // 비정상적으로 큰 Content-Length → 버퍼 클리어
        buffer.clear();
        return false;
    }

    // 전체 메시지 크기 확인
    std::size_t totalSize = bodyStart + contentLength;
    if (buffer.size() < totalSize)
    {
        return false;  // 바디가 아직 완전하지 않음
    }

    // 메시지 추출
    message = buffer.substr(0, totalSize);
    buffer.erase(0, totalSize);
    return true;
}

void TcpServer::recvLoop()
{
    Logger::instance().info("[TcpServer] recvLoop started (epoll)");

    // 리스닝 소켓을 epoll에 등록
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listenSock_.load();
    if (::epoll_ctl(epollFd_, EPOLL_CTL_ADD, listenSock_.load(), &ev) < 0)
    {
        logError("epoll_ctl(listen)");
        return;
    }

    struct epoll_event events[EPOLL_MAX_EVENTS];
    char readBuf[RECV_BUFFER_SIZE];

    while (running_)
    {
        int nfds = ::epoll_wait(epollFd_, events, EPOLL_MAX_EVENTS, 500);  // 500ms 타임아웃
        if (nfds < 0)
        {
            if (errno == EINTR) continue;
            if (!running_) break;
            logError("epoll_wait");
            continue;
        }

        for (int i = 0; i < nfds; ++i)
        {
            int fd = events[i].data.fd;

            // 새 연결 수락
            if (fd == listenSock_.load())
            {
                while (true)
                {
                    sockaddr_in clientAddr;
                    socklen_t clientLen = sizeof(clientAddr);
                    std::memset(&clientAddr, 0, sizeof(clientAddr));

                    int clientFd = ::accept(listenSock_.load(),
                                            reinterpret_cast<sockaddr*>(&clientAddr),
                                            &clientLen);
                    if (clientFd < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;  // 더 이상 대기 중인 연결 없음
                        logError("accept");
                        break;
                    }

                    // 논블로킹 설정
                    if (!setNonBlocking(clientFd))
                    {
                        ::close(clientFd);
                        continue;
                    }

                    // TCP_NODELAY
                    int nodelay = 1;
                    ::setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                    char ipStr[INET_ADDRSTRLEN];
                    ::inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
                    uint16_t clientPort = ntohs(clientAddr.sin_port);

                    addConnection(clientFd, ipStr, clientPort);
                    Logger::instance().info(std::string("[TcpServer] New connection from ")
                        + ipStr + ":" + std::to_string(clientPort));
                }
                continue;
            }

            // 에러 또는 연결 종료
            if (events[i].events & (EPOLLERR | EPOLLHUP))
            {
                removeConnection(fd);
                continue;
            }

            // 데이터 수신
            if (events[i].events & EPOLLIN)
            {
                bool connectionClosed = false;

                while (true)
                {
                    ssize_t n = ::read(fd, readBuf, sizeof(readBuf) - 1);
                    if (n < 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;  // 더 이상 읽을 데이터 없음
                        connectionClosed = true;
                        break;
                    }
                    if (n == 0)
                    {
                        connectionClosed = true;
                        break;
                    }

                    // 연결 정보 가져오기
                    std::string remoteIp;
                    uint16_t remotePort = 0;

                    {
                        std::lock_guard<std::mutex> lock(connMutex_);
                        auto it = connections_.find(fd);
                        if (it == connections_.end())
                        {
                            connectionClosed = true;
                            break;
                        }

                        // 수신 버퍼에 추가
                        it->second.recvBuffer.append(readBuf, static_cast<std::size_t>(n));
                        it->second.lastActive = std::chrono::steady_clock::now();

                        // 수신 버퍼 크기 제한
                        if (it->second.recvBuffer.size() > MAX_RECV_BUFFER)
                        {
                            Logger::instance().error("[TcpServer] Recv buffer overflow from "
                                + it->second.remoteIp + ":" + std::to_string(it->second.remotePort));
                            connectionClosed = true;
                            break;
                        }

                        remoteIp = it->second.remoteIp;
                        remotePort = it->second.remotePort;

                        // 완전한 SIP 메시지 추출 및 디스패치
                        std::string sipMsg;
                        while (extractSipMessage(it->second.recvBuffer, sipMsg))
                        {
                            UdpPacket pkt;
                            pkt.remoteIp = remoteIp;
                            pkt.remotePort = remotePort;
                            pkt.data = std::move(sipMsg);
                            pkt.transport = TransportType::TCP;

                            // Call-ID 기반 워커 라우팅
                            std::string callId = extractCallIdQuick(pkt.data);
                            std::size_t workerIdx = callId.empty() ? 0 : routeToWorker(callId);

                            if (!workerQueues_[workerIdx]->push(std::move(pkt)))
                            {
                                Logger::instance().error(std::string("[TcpServer] Worker queue[")
                                    + std::to_string(workerIdx) + "] full, dropping TCP packet from "
                                    + remoteIp + ":" + std::to_string(remotePort));
                            }
                        }
                    }
                }

                if (connectionClosed)
                {
                    removeConnection(fd);
                }
            }
        }
    }

    Logger::instance().info("[TcpServer] recvLoop ended");
}

void TcpServer::workerLoop(std::size_t workerId)
{
    Logger::instance().info(std::string("[TcpServer] Worker ") + std::to_string(workerId) + " started");

    while (true)
    {
        UdpPacket pkt;
        if (!workerQueues_[workerId]->pop(pkt))
        {
            break;
        }

        handlePacket(workerId, pkt);
    }

    Logger::instance().info(std::string("[TcpServer] Worker ") + std::to_string(workerId) + " ended");
}

void TcpServer::handlePacket(std::size_t workerId, const UdpPacket& pkt)
{
    constexpr std::size_t MIN_SIP_SIZE = 20;

    if (pkt.data.size() < MIN_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_tcpLogMutex);
        std::cerr << "[TCP Worker " << workerId << "] Packet too small from "
                  << pkt.remoteIp << ":" << pkt.remotePort
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }

    if (pkt.data.size() > MAX_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_tcpLogMutex);
        std::cerr << "[TCP Worker " << workerId << "] Packet too large from "
                  << pkt.remoteIp << ":" << pkt.remotePort
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }

    if (isVerboseSipLoggingEnabled())
    {
        std::lock_guard<std::mutex> lock(g_tcpLogMutex);
        std::cout << "------------------------------------------\n";
        std::cout << "[TCP Worker " << workerId << "] from "
                << pkt.remoteIp << ":" << pkt.remotePort << "\n";
        std::cout << sanitizeSipForLog(pkt.data, MAX_LOG_DATA_LENGTH) << "\n";
    }

    // SIP 메시지 파싱
    SipMessage msg;
    if (!parseSipMessage(pkt.data, msg))
    {
        std::lock_guard<std::mutex> lock(g_tcpLogMutex);
        Logger::instance().info("[TCP Worker " + std::to_string(workerId)
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
                if (sendTo(pkt.remoteIp, pkt.remotePort, response))
                {
                    if (isVerboseSipLoggingEnabled())
                    {
                        std::lock_guard<std::mutex> lock(g_tcpLogMutex);
                        std::cout << "[TCP Worker " << workerId << "] SIP response sent to "
                                  << pkt.remoteIp << ":" << pkt.remotePort << "\n";
                        std::cout << sanitizeSipForLog(response, MAX_LOG_DATA_LENGTH) << "\n";
                    }
                }
                else
                {
                    std::lock_guard<std::mutex> lock(g_tcpLogMutex);
                    std::cerr << "[TCP Worker " << workerId << "] Failed to send SIP response\n";
                }
            }
        }
        else
        {
            std::lock_guard<std::mutex> lock(g_tcpLogMutex);
            std::cerr << "[TCP Worker " << workerId << "] Failed to handle SIP request\n";
        }
    }
    else
    {
        if (sipCore_.handleResponse(pkt, msg))
        {
            std::lock_guard<std::mutex> lock(g_tcpLogMutex);
            std::cout << "[TCP Worker " << workerId << "] Forwarded SIP response for Call-ID "
                      << sanitizeForDisplay(getHeader(msg, "call-id"), MAX_LOG_DATA_LENGTH) << "\n";
        }
        else
        {
            std::lock_guard<std::mutex> lock(g_tcpLogMutex);
            std::cerr << "[TCP Worker " << workerId << "] Unhandled SIP response\n";
        }
    }
}

bool TcpServer::sendTo(const std::string& ip, uint16_t port, const std::string& data)
{
    if (data.empty()) return false;

    int fd = findOrCreateConnection(ip, port);
    if (fd < 0)
    {
        Logger::instance().error("[TcpServer] Cannot send to " + ip + ":" + std::to_string(port)
            + " (no connection)");
        return false;
    }

    std::shared_ptr<std::mutex> ioMutex;
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end() || !it->second.ioMutex)
        {
            return false;
        }
        ioMutex = it->second.ioMutex;
    }

    // TCP는 스트림이므로 전체 데이터를 보낼 때까지 반복
    const char* ptr = data.c_str();
    std::size_t remaining = data.size();
    bool sendFailed = false;

    {
        std::lock_guard<std::mutex> ioLock(*ioMutex);
        while (remaining > 0)
        {
            ssize_t sent = ::send(fd, ptr, remaining, MSG_NOSIGNAL);
            if (sent < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // 잠시 대기 후 재시도
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                logError("send(TCP)");
                sendFailed = true;
                break;
            }
            ptr += sent;
            remaining -= static_cast<std::size_t>(sent);
        }
    }

    if (sendFailed)
    {
        removeConnection(fd);
        return false;
    }

    return true;
}
