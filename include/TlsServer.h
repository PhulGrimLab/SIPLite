#pragma once

#include "concurrent_queue.h"
#include "UdpPacket.h"
#include "SipCore.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

struct TlsVerifyConfig
{
    bool verifyPeer = false;          // outbound peer cert chain verification
    bool requireClientCert = false;   // inbound client certificate requirement
    std::string caFile;
};

struct TlsConnection
{
    int fd = -1;
    SSL* ssl = nullptr;
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string recvBuffer;
    std::chrono::steady_clock::time_point lastActive;
    std::mutex ioMutex;
};

class TlsServer
{
public:
    explicit TlsServer(SipCore& sipCore);
    ~TlsServer();

    TlsServer(const TlsServer&) = delete;
    TlsServer& operator=(const TlsServer&) = delete;
    TlsServer(TlsServer&&) = delete;
    TlsServer& operator=(TlsServer&&) = delete;

    bool start(const std::string& ip,
               uint16_t port,
               std::size_t workerCount,
               const std::string& certFile,
               const std::string& keyFile);
    void stop();

    bool sendTo(const std::string& ip, uint16_t port, const std::string& data);
    std::size_t connectionCount() const;
    bool hasConnection(const std::string& ip, uint16_t port) const;

private:
    bool initializeSsl(const std::string& certFile, const std::string& keyFile);
    bool configureVerification();
    void cleanupSsl();
    bool bindSocket(const std::string& ip, uint16_t port);
    void recvLoop();
    void workerLoop(std::size_t workerId);
    void handlePacket(std::size_t workerId, const UdpPacket& pkt);
    bool extractSipMessage(std::string& buffer, std::string& message);

    void addConnection(std::shared_ptr<TlsConnection> conn);
    void removeConnection(int fd);
    int findOrCreateConnection(const std::string& ip, uint16_t port);

    std::size_t routeToWorker(const std::string& callId) const;
    static std::string extractCallIdQuick(const std::string& data);

private:
    std::atomic<int> listenSock_;
    std::atomic<bool> running_;
    std::thread recvThread_;
    std::vector<std::thread> workerThreads_;

    std::vector<std::unique_ptr<ConcurrentQueue<UdpPacket>>> workerQueues_;
    std::size_t workerCount_ = 0;

    mutable std::mutex connMutex_;
    std::unordered_map<int, std::shared_ptr<TlsConnection>> connections_;

    mutable std::mutex outConnMutex_;
    std::unordered_map<std::string, int> outgoingConns_;

    SipCore& sipCore_;
    SSL_CTX* serverCtx_ = nullptr;
    SSL_CTX* clientCtx_ = nullptr;
    TlsVerifyConfig verifyConfig_;
    std::string bindIp_;
    uint16_t bindPort_ = 0;

    static constexpr std::size_t RECV_BUFFER_SIZE = 65536;
    static constexpr std::size_t MAX_SIP_SIZE = 65536;
    static constexpr std::size_t MAX_RECV_BUFFER = 256 * 1024;
    static constexpr int MAX_CONNECTIONS = 1024;
    static constexpr int EPOLL_MAX_EVENTS = 64;
};
