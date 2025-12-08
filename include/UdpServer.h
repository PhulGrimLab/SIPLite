#pragma once

#include "concurrent_queue.h"
#include "UdpPacket.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

class UdpServer 
{
public:
    UdpServer();
    ~UdpServer();

    // 복사/이동 금지
    UdpServer(const UdpServer&) = delete;
    UdpServer& operator=(const UdpServer&) = delete;
    UdpServer(UdpServer&&) = delete;
    UdpServer& operator=(UdpServer&&) = delete;

    // ip: "0.0.0.0", port: 5060, workerCount: 워커 스레드 수
    bool start(const std::string& ip, uint16_t port, std::size_t workerCount);
    void stop();

    // 클라이언트에게 데이터 전송
    bool sendTo(const std::string& ip, uint16_t port, const std::string& data);

private:
    bool bindSocket(const std::string& ip, uint16_t port);
    void recvLoop();
    void workerLoop(std::size_t workerId);
    void handlePacket(std::size_t workerId, const UdpPacket& pkt);

private:
    std::atomic<int> sock_;
    std::atomic<bool> running_;
    std::thread recvThread_;
    std::vector<std::thread> workerThreads_;
    ConcurrentQueue<UdpPacket> queue_;
};
