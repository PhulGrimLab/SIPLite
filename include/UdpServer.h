#pragma once

#include "concurrent_queue.h"
#include "UdpPacket.h"
#include "SipCore.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <memory>

class UdpServer
{
public:
    UdpServer();
    ~UdpServer();

    // 복사/이동 금지
    UdpServer(const UdpServer&) = delete;               // 복사 생성자 삭제
    UdpServer& operator=(const UdpServer&) = delete;    // 복사 할당 연산자 삭제
    UdpServer(UdpServer&&) = delete;                    // 이동 생성자 삭제
    UdpServer& operator=(UdpServer&&) = delete;         // 이동 할당 연산자 삭제

    // ip: "0.0.0.0", port: 5060, workerCount: 워커 스레드 수
    bool start(const std::string& ip, uint16_t port, std::size_t workerCount);
    void stop();

    // 클라이언트에게 데이터 전송
    bool sendTo(const std::string& ip, uint16_t port, const std::string& data);

    // SIP 코어 접근
    SipCore& sipCore() { return sipCore_; }
    const SipCore& sipCore() const { return sipCore_; }

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
    
    SipCore sipCore_;
};