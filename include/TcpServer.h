#pragma once

#include "concurrent_queue.h"
#include "UdpPacket.h"
#include "SipCore.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>

// TCP 연결 정보
struct TcpConnection
{
    int fd = -1;
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string recvBuffer;     // 수신 버퍼 (스트림 프레이밍용)
    std::chrono::steady_clock::time_point lastActive;
};

class TcpServer
{
public:
    // SipCore 참조를 받아 UDP 서버와 공유 (등록/통화 상태 공유)
    explicit TcpServer(SipCore& sipCore);
    ~TcpServer();

    // 복사/이동 금지
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    TcpServer(TcpServer&&) = delete;
    TcpServer& operator=(TcpServer&&) = delete;

    // ip: "0.0.0.0", port: 5060, workerCount: 워커 스레드 수
    bool start(const std::string& ip, uint16_t port, std::size_t workerCount);
    void stop();

    // 지정된 IP:Port로 데이터 전송 (기존 연결 재사용 또는 새 연결 생성)
    bool sendTo(const std::string& ip, uint16_t port, const std::string& data);

    // 활성 TCP 연결 수
    std::size_t connectionCount() const;

    // 지정된 IP:Port에 대한 활성 TCP 연결이 있는지 확인
    bool hasConnection(const std::string& ip, uint16_t port) const;

private:
    bool bindSocket(const std::string& ip, uint16_t port);
    void acceptLoop();                              // 연결 수락 루프
    void recvLoop();                                // epoll 기반 수신 루프
    void workerLoop(std::size_t workerId);          // 워커 스레드
    void handlePacket(std::size_t workerId, const UdpPacket& pkt);

    // SIP 메시지 프레이밍: 수신 버퍼에서 완전한 SIP 메시지 추출
    bool extractSipMessage(std::string& buffer, std::string& message);

    // 연결 관리
    void addConnection(int fd, const std::string& ip, uint16_t port);
    void removeConnection(int fd);
    int findOrCreateConnection(const std::string& ip, uint16_t port);

    // Call-ID 기반 워커 라우팅
    std::size_t routeToWorker(const std::string& callId) const;
    static std::string extractCallIdQuick(const std::string& data);

private:
    std::atomic<int> listenSock_;       // 리스닝 소켓
    int epollFd_ = -1;                  // epoll 파일 디스크립터
    std::atomic<bool> running_;
    std::thread acceptThread_;
    std::thread recvThread_;
    std::vector<std::thread> workerThreads_;

    // 워커별 전용 큐
    std::vector<std::unique_ptr<ConcurrentQueue<UdpPacket>>> workerQueues_;
    std::size_t workerCount_ = 0;

    // TCP 연결 관리 (fd → TcpConnection)
    mutable std::mutex connMutex_;
    std::unordered_map<int, TcpConnection> connections_;

    // IP:Port → fd 역방향 매핑 (송신 시 기존 연결 재사용용)
    mutable std::mutex outConnMutex_;
    std::unordered_map<std::string, int> outgoingConns_;  // "ip:port" → fd

    SipCore& sipCore_;  // UdpServer와 공유하는 SipCore 참조

    // 바인딩된 로컬 주소 정보 (아웃바운드 연결 시 사용)
    std::string bindIp_;
    uint16_t bindPort_ = 0;

    // 상수
    static constexpr std::size_t RECV_BUFFER_SIZE = 65536;
    static constexpr std::size_t MAX_SIP_SIZE = 65536;
    static constexpr std::size_t MAX_RECV_BUFFER = 256 * 1024;  // 연결당 최대 수신 버퍼
    static constexpr int MAX_CONNECTIONS = 1024;                 // 최대 동시 연결 수
    static constexpr int EPOLL_MAX_EVENTS = 64;
};