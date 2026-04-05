#include "TlsServer.h"
#include "SipUtils.h"
#include "Logger.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <cstdlib>

namespace
{
    std::mutex g_tlsLogMutex;
    constexpr std::size_t MAX_LOG_DATA_LENGTH = 200;

    bool setNonBlocking(int fd)
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0)
        {
            return false;
        }
        return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
    }

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
                while (pos < data.size() && data[pos] == ' ')
                {
                    ++pos;
                }
                auto end = data.find("\r\n", pos);
                if (end == std::string::npos)
                {
                    end = data.size();
                }
                std::string callId = data.substr(pos, end - pos);
                while (!callId.empty() && callId.back() == ' ')
                {
                    callId.pop_back();
                }
                return callId;
            }
        }

        return {};
    }

    void logError(const char* prefix)
    {
        int savedErrno = errno;
        char buf[256];
        std::string s;
#if (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) && !defined(_GNU_SOURCE)
        if (strerror_r(savedErrno, buf, sizeof(buf)) == 0)
        {
            s = std::string(prefix) + ": " + buf + " (errno=" + std::to_string(savedErrno) + ")";
        }
        else
        {
            s = std::string(prefix) + ": errno=" + std::to_string(savedErrno);
        }
#else
        char* result = strerror_r(savedErrno, buf, sizeof(buf));
        s = std::string(prefix) + ": " + result + " (errno=" + std::to_string(savedErrno) + ")";
#endif
        Logger::instance().error(s);
    }

    void logSslError(const std::string& prefix)
    {
        unsigned long err = ERR_get_error();
        if (err == 0)
        {
            Logger::instance().error(prefix);
            return;
        }

        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        Logger::instance().error(prefix + ": " + std::string(buf));
    }

    bool envEnabled(const char* name, bool defaultValue = false)
    {
        const char* raw = std::getenv(name);
        if (raw == nullptr || *raw == '\0')
        {
            return defaultValue;
        }

        const std::string value = toLower(trim(raw));
        if (value == "1" || value == "true" || value == "yes" || value == "on")
        {
            return true;
        }
        if (value == "0" || value == "false" || value == "no" || value == "off")
        {
            return false;
        }

        Logger::instance().error(std::string("[TlsServer] Invalid boolean env ")
            + name + "=" + raw + ", using default");
        return defaultValue;
    }
}

TlsServer::TlsServer(SipCore& sipCore)
    : listenSock_(-1), running_(false), sipCore_(sipCore)
{
}

TlsServer::~TlsServer()
{
    stop();
}

std::string TlsServer::extractCallIdQuick(const std::string& data)
{
    return extractCallIdQuickImpl(data);
}

std::size_t TlsServer::routeToWorker(const std::string& callId) const
{
    if (workerCount_ == 0)
    {
        return 0;
    }
    std::size_t hash = std::hash<std::string>{}(callId);
    return hash % workerCount_;
}

std::size_t TlsServer::connectionCount() const
{
    std::lock_guard<std::mutex> lock(connMutex_);
    return connections_.size();
}

bool TlsServer::hasConnection(const std::string& ip, uint16_t port) const
{
    std::lock_guard<std::mutex> lock(connMutex_);
    for (const auto& [fd, conn] : connections_)
    {
        if (conn->remoteIp == ip && conn->remotePort == port)
        {
            return true;
        }
    }
    return false;
}

bool TlsServer::initializeSsl(const std::string& certFile, const std::string& keyFile)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    verifyConfig_.verifyPeer = envEnabled("SIPLITE_TLS_VERIFY_PEER", false);
    verifyConfig_.requireClientCert = envEnabled("SIPLITE_TLS_REQUIRE_CLIENT_CERT", false);
    if (const char* caFile = std::getenv("SIPLITE_TLS_CA_FILE"))
    {
        verifyConfig_.caFile = trim(caFile);
    }

    serverCtx_ = SSL_CTX_new(TLS_server_method());
    clientCtx_ = SSL_CTX_new(TLS_client_method());
    if (serverCtx_ == nullptr || clientCtx_ == nullptr)
    {
        logSslError("[TlsServer] SSL_CTX_new failed");
        return false;
    }

    SSL_CTX_set_min_proto_version(serverCtx_, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(clientCtx_, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(serverCtx_, certFile.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        logSslError("[TlsServer] Failed to load certificate");
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(serverCtx_, keyFile.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        logSslError("[TlsServer] Failed to load private key");
        return false;
    }
    if (SSL_CTX_check_private_key(serverCtx_) != 1)
    {
        logSslError("[TlsServer] Certificate/private key mismatch");
        return false;
    }

    if (!configureVerification())
    {
        return false;
    }

    Logger::instance().info("[TlsServer] Verification policy: verifyPeer="
        + std::string(verifyConfig_.verifyPeer ? "on" : "off")
        + ", requireClientCert="
        + std::string(verifyConfig_.requireClientCert ? "on" : "off")
        + ", caFile="
        + (verifyConfig_.caFile.empty() ? "(system default / none)" : verifyConfig_.caFile));
    if (verifyConfig_.verifyPeer)
    {
        Logger::instance().info("[TlsServer] Outbound peer certificate chain verification enabled"
            " (hostname verification is still not implemented)");
    }

    return true;
}

bool TlsServer::configureVerification()
{
    auto loadCaStore = [this](SSL_CTX* ctx, const char* roleLabel) -> bool {
        if (!verifyConfig_.caFile.empty())
        {
            if (SSL_CTX_load_verify_locations(ctx, verifyConfig_.caFile.c_str(), nullptr) != 1)
            {
                logSslError(std::string("[TlsServer] Failed to load CA file for ") + roleLabel);
                return false;
            }
            return true;
        }

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        {
            logSslError(std::string("[TlsServer] Failed to load default CA paths for ") + roleLabel);
            return false;
        }
        return true;
    };

    if (verifyConfig_.verifyPeer)
    {
        if (!loadCaStore(clientCtx_, "outbound TLS"))
        {
            return false;
        }
        SSL_CTX_set_verify(clientCtx_, SSL_VERIFY_PEER, nullptr);
    }
    else
    {
        SSL_CTX_set_verify(clientCtx_, SSL_VERIFY_NONE, nullptr);
    }

    if (verifyConfig_.requireClientCert)
    {
        if (!loadCaStore(serverCtx_, "inbound TLS"))
        {
            return false;
        }
        SSL_CTX_set_verify(serverCtx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    else
    {
        SSL_CTX_set_verify(serverCtx_, SSL_VERIFY_NONE, nullptr);
    }

    return true;
}

void TlsServer::cleanupSsl()
{
    if (serverCtx_ != nullptr)
    {
        SSL_CTX_free(serverCtx_);
        serverCtx_ = nullptr;
    }
    if (clientCtx_ != nullptr)
    {
        SSL_CTX_free(clientCtx_);
        clientCtx_ = nullptr;
    }
}

bool TlsServer::start(const std::string& ip,
                      uint16_t port,
                      std::size_t workerCount,
                      const std::string& certFile,
                      const std::string& keyFile)
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true))
    {
        std::cerr << "[TlsServer] Already running\n";
        return false;
    }

    bindIp_ = ip;
    bindPort_ = port;
    workerCount_ = workerCount;

    workerQueues_.clear();
    workerQueues_.reserve(workerCount);
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerQueues_.push_back(std::make_unique<ConcurrentQueue<UdpPacket>>());
    }

    if (!initializeSsl(certFile, keyFile))
    {
        running_.store(false);
        workerQueues_.clear();
        cleanupSsl();
        return false;
    }

    if (!bindSocket(ip, port))
    {
        running_.store(false);
        workerQueues_.clear();
        cleanupSsl();
        return false;
    }

    recvThread_ = std::thread(&TlsServer::recvLoop, this);
    for (std::size_t i = 0; i < workerCount; ++i)
    {
        workerThreads_.emplace_back(&TlsServer::workerLoop, this, i);
    }

    Logger::instance().info("[TlsServer] started at " + ip + ":" + std::to_string(port)
        + " with " + std::to_string(workerCount) + " workers");
    return true;
}

void TlsServer::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false))
    {
        return;
    }

    for (auto& q : workerQueues_)
    {
        q->shutdown();
    }

    int sock = listenSock_.exchange(-1);
    if (sock >= 0)
    {
        ::close(sock);
    }

    {
        std::lock_guard<std::mutex> lock(connMutex_);
        for (auto& [fd, conn] : connections_)
        {
            if (conn->ssl != nullptr)
            {
                SSL_shutdown(conn->ssl);
                SSL_free(conn->ssl);
                conn->ssl = nullptr;
            }
            if (fd >= 0)
            {
                ::close(fd);
            }
        }
        connections_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        outgoingConns_.clear();
    }

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
    cleanupSsl();

    Logger::instance().info("[TlsServer] Stopped");
}

bool TlsServer::bindSocket(const std::string& ip, uint16_t port)
{
    listenSock_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock_ < 0)
    {
        logError("socket(TLS)");
        return false;
    }

    int reuse = 1;
    if (::setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        logError("setsockopt(SO_REUSEADDR)");
    }

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
        Logger::instance().error("[TlsServer] Invalid IP address: " + ip);
        int s = listenSock_.exchange(-1);
        if (s >= 0)
        {
            ::close(s);
        }
        return false;
    }

    if (::bind(listenSock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        logError("bind(TLS)");
        int s = listenSock_.exchange(-1);
        if (s >= 0)
        {
            ::close(s);
        }
        return false;
    }

    if (!setNonBlocking(listenSock_))
    {
        logError("fcntl(TLS listen)");
        int s = listenSock_.exchange(-1);
        if (s >= 0)
        {
            ::close(s);
        }
        return false;
    }

    if (::listen(listenSock_, 128) < 0)
    {
        logError("listen(TLS)");
        int s = listenSock_.exchange(-1);
        if (s >= 0)
        {
            ::close(s);
        }
        return false;
    }

    Logger::instance().info("[TlsServer] bind TLS " + ip + ":" + std::to_string(port) + " 성공");
    return true;
}

void TlsServer::addConnection(std::shared_ptr<TlsConnection> conn)
{
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        if (connections_.size() >= static_cast<std::size_t>(MAX_CONNECTIONS))
        {
            Logger::instance().error("[TlsServer] Max connections reached, rejecting "
                + conn->remoteIp + ":" + std::to_string(conn->remotePort));
            if (conn->ssl != nullptr)
            {
                SSL_shutdown(conn->ssl);
                SSL_free(conn->ssl);
            }
            if (conn->fd >= 0)
            {
                ::close(conn->fd);
            }
            return;
        }
        connections_[conn->fd] = conn;
    }
}

void TlsServer::removeConnection(int fd)
{
    std::shared_ptr<TlsConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end())
        {
            return;
        }
        conn = it->second;
        connections_.erase(it);
    }

    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        for (auto it = outgoingConns_.begin(); it != outgoingConns_.end();)
        {
            if (it->second == fd)
            {
                it = outgoingConns_.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    if (conn != nullptr)
    {
        std::lock_guard<std::mutex> ioLock(conn->ioMutex);
        if (conn->ssl != nullptr)
        {
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            conn->ssl = nullptr;
        }
        if (conn->fd >= 0)
        {
            ::close(conn->fd);
            conn->fd = -1;
        }
        Logger::instance().info("[TlsServer] Connection closed: "
            + conn->remoteIp + ":" + std::to_string(conn->remotePort));
    }
}

int TlsServer::findOrCreateConnection(const std::string& ip, uint16_t port)
{
    std::string key = ip + ":" + std::to_string(port);

    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        auto it = outgoingConns_.find(key);
        if (it != outgoingConns_.end())
        {
            std::lock_guard<std::mutex> lockConn(connMutex_);
            if (connections_.count(it->second) != 0)
            {
                return it->second;
            }
            outgoingConns_.erase(it);
        }
    }

    {
        std::lock_guard<std::mutex> lock(connMutex_);
        for (const auto& [fd, conn] : connections_)
        {
            if (conn->remoteIp == ip && conn->remotePort == port)
            {
                std::lock_guard<std::mutex> lockOut(outConnMutex_);
                outgoingConns_[key] = fd;
                return fd;
            }
        }
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        logError("socket(TLS outbound)");
        return -1;
    }

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

    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        logError("connect(TLS outbound)");
        ::close(fd);
        return -1;
    }

    SSL* ssl = SSL_new(clientCtx_);
    if (ssl == nullptr)
    {
        logSslError("[TlsServer] SSL_new(client) failed");
        ::close(fd);
        return -1;
    }

    if (verifyConfig_.verifyPeer)
    {
        X509_VERIFY_PARAM* verifyParams = SSL_get0_param(ssl);
        if (verifyParams == nullptr || X509_VERIFY_PARAM_set1_ip_asc(verifyParams, ip.c_str()) != 1)
        {
            Logger::instance().error("[TlsServer] Failed to configure peer IP verification for " + key);
            SSL_free(ssl);
            ::close(fd);
            return -1;
        }
    }

    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1)
    {
        logSslError("[TlsServer] SSL_connect failed");
        SSL_free(ssl);
        ::close(fd);
        return -1;
    }
    if (verifyConfig_.verifyPeer && SSL_get_verify_result(ssl) != X509_V_OK)
    {
        Logger::instance().error("[TlsServer] Peer certificate verification failed after SSL_connect");
        SSL_free(ssl);
        ::close(fd);
        return -1;
    }

    if (!setNonBlocking(fd))
    {
        SSL_free(ssl);
        ::close(fd);
        return -1;
    }

    auto conn = std::make_shared<TlsConnection>();
    conn->fd = fd;
    conn->ssl = ssl;
    conn->remoteIp = ip;
    conn->remotePort = port;
    conn->lastActive = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(connMutex_);
        connections_[fd] = conn;
    }
    {
        std::lock_guard<std::mutex> lock(outConnMutex_);
        outgoingConns_[key] = fd;
    }

    Logger::instance().info("[TlsServer] Outbound TLS connection to " + key);
    return fd;
}

bool TlsServer::extractSipMessage(std::string& buffer, std::string& message)
{
    auto headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
        return false;
    }

    std::size_t bodyStart = headerEnd + 4;
    std::size_t contentLength = 0;
    static const char* clPatterns[] = {
        "\r\nContent-Length:", "\r\ncontent-length:", "\r\nContent-length:",
        "\r\nl:", nullptr
    };

    std::string headers = buffer.substr(0, bodyStart);
    for (const char** p = clPatterns; *p; ++p)
    {
        auto pos = headers.find(*p);
        if (pos != std::string::npos)
        {
            pos += std::strlen(*p);
            while (pos < headers.size() && headers[pos] == ' ')
            {
                ++pos;
            }
            auto end = headers.find("\r\n", pos);
            if (end == std::string::npos)
            {
                end = headers.size();
            }
            std::string clStr = headers.substr(pos, end - pos);
            while (!clStr.empty() && clStr.back() == ' ')
            {
                clStr.pop_back();
            }
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

    if (contentLength > MAX_SIP_SIZE)
    {
        buffer.clear();
        return false;
    }

    std::size_t totalSize = bodyStart + contentLength;
    if (buffer.size() < totalSize)
    {
        return false;
    }

    message = buffer.substr(0, totalSize);
    buffer.erase(0, totalSize);
    return true;
}

void TlsServer::recvLoop()
{
    Logger::instance().info("[TlsServer] recvLoop started (epoll)");

    int epollFd = ::epoll_create1(0);
    if (epollFd < 0)
    {
        logError("epoll_create1(TLS)");
        return;
    }

    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listenSock_.load();
    if (::epoll_ctl(epollFd, EPOLL_CTL_ADD, listenSock_.load(), &ev) < 0)
    {
        logError("epoll_ctl(TLS listen)");
        ::close(epollFd);
        return;
    }

    epoll_event events[EPOLL_MAX_EVENTS];
    char readBuf[RECV_BUFFER_SIZE];

    while (running_)
    {
        int nfds = ::epoll_wait(epollFd, events, EPOLL_MAX_EVENTS, 500);
        if (nfds < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (!running_)
            {
                break;
            }
            logError("epoll_wait(TLS)");
            continue;
        }

        for (int i = 0; i < nfds; ++i)
        {
            int fd = events[i].data.fd;
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
                        {
                            break;
                        }
                        logError("accept(TLS)");
                        break;
                    }

                    SSL* ssl = SSL_new(serverCtx_);
                    if (ssl == nullptr)
                    {
                        logSslError("[TlsServer] SSL_new(server) failed");
                        ::close(clientFd);
                        continue;
                    }

                    SSL_set_fd(ssl, clientFd);
                    if (SSL_accept(ssl) != 1)
                    {
                        logSslError("[TlsServer] SSL_accept failed");
                        SSL_free(ssl);
                        ::close(clientFd);
                        continue;
                    }

                    if (!setNonBlocking(clientFd))
                    {
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        ::close(clientFd);
                        continue;
                    }

                    int nodelay = 1;
                    ::setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                    char ipStr[INET_ADDRSTRLEN];
                    ::inet_ntop(AF_INET, &clientAddr.sin_addr, ipStr, sizeof(ipStr));
                    uint16_t clientPort = ntohs(clientAddr.sin_port);

                    auto conn = std::make_shared<TlsConnection>();
                    conn->fd = clientFd;
                    conn->ssl = ssl;
                    conn->remoteIp = ipStr;
                    conn->remotePort = clientPort;
                    conn->lastActive = std::chrono::steady_clock::now();

                    {
                        std::lock_guard<std::mutex> lock(connMutex_);
                        connections_[clientFd] = conn;
                    }

                    epoll_event clientEv;
                    clientEv.events = EPOLLIN | EPOLLET;
                    clientEv.data.fd = clientFd;
                    if (::epoll_ctl(epollFd, EPOLL_CTL_ADD, clientFd, &clientEv) < 0)
                    {
                        logError("epoll_ctl(TLS client)");
                        removeConnection(clientFd);
                        continue;
                    }

                    Logger::instance().info("[TlsServer] New TLS connection from "
                        + std::string(ipStr) + ":" + std::to_string(clientPort));
                }
                continue;
            }

            if (events[i].events & (EPOLLERR | EPOLLHUP))
            {
                removeConnection(fd);
                continue;
            }

            if (events[i].events & EPOLLIN)
            {
                std::shared_ptr<TlsConnection> conn;
                {
                    std::lock_guard<std::mutex> lock(connMutex_);
                    auto it = connections_.find(fd);
                    if (it != connections_.end())
                    {
                        conn = it->second;
                    }
                }
                if (conn == nullptr)
                {
                    continue;
                }

                bool connectionClosed = false;
                std::lock_guard<std::mutex> ioLock(conn->ioMutex);
                while (true)
                {
                    int n = SSL_read(conn->ssl, readBuf, static_cast<int>(sizeof(readBuf)));
                    if (n <= 0)
                    {
                        int sslErr = SSL_get_error(conn->ssl, n);
                        if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE)
                        {
                            break;
                        }
                        if (sslErr == SSL_ERROR_ZERO_RETURN)
                        {
                            connectionClosed = true;
                            break;
                        }
                        logSslError("[TlsServer] SSL_read failed");
                        connectionClosed = true;
                        break;
                    }

                    conn->recvBuffer.append(readBuf, static_cast<std::size_t>(n));
                    conn->lastActive = std::chrono::steady_clock::now();
                    if (conn->recvBuffer.size() > MAX_RECV_BUFFER)
                    {
                        Logger::instance().error("[TlsServer] Recv buffer overflow from "
                            + conn->remoteIp + ":" + std::to_string(conn->remotePort));
                        connectionClosed = true;
                        break;
                    }

                    std::string sipMsg;
                    while (extractSipMessage(conn->recvBuffer, sipMsg))
                    {
                        UdpPacket pkt;
                        pkt.remoteIp = conn->remoteIp;
                        pkt.remotePort = conn->remotePort;
                        pkt.data = std::move(sipMsg);
                        pkt.transport = TransportType::TLS;

                        std::string callId = extractCallIdQuick(pkt.data);
                        std::size_t workerIdx = callId.empty() ? 0 : routeToWorker(callId);
                        if (!workerQueues_[workerIdx]->push(std::move(pkt)))
                        {
                            Logger::instance().error("[TlsServer] Worker queue[" + std::to_string(workerIdx)
                                + "] full, dropping TLS packet from "
                                + conn->remoteIp + ":" + std::to_string(conn->remotePort));
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

    ::close(epollFd);
    Logger::instance().info("[TlsServer] recvLoop ended");
}

void TlsServer::workerLoop(std::size_t workerId)
{
    Logger::instance().info("[TlsServer] Worker " + std::to_string(workerId) + " started");

    while (true)
    {
        UdpPacket pkt;
        if (!workerQueues_[workerId]->pop(pkt))
        {
            break;
        }
        handlePacket(workerId, pkt);
    }

    Logger::instance().info("[TlsServer] Worker " + std::to_string(workerId) + " ended");
}

void TlsServer::handlePacket(std::size_t workerId, const UdpPacket& pkt)
{
    constexpr std::size_t MIN_SIP_SIZE = 20;
    if (pkt.data.size() < MIN_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_tlsLogMutex);
        std::cerr << "[TLS Worker " << workerId << "] Packet too small from "
                  << pkt.remoteIp << ":" << pkt.remotePort
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }

    if (pkt.data.size() > MAX_SIP_SIZE)
    {
        std::lock_guard<std::mutex> lock(g_tlsLogMutex);
        std::cerr << "[TLS Worker " << workerId << "] Packet too large from "
                  << pkt.remoteIp << ":" << pkt.remotePort
                  << " (" << pkt.data.size() << " bytes)\n";
        return;
    }

    if (isVerboseSipLoggingEnabled())
    {
        std::lock_guard<std::mutex> lock(g_tlsLogMutex);
        std::cout << "------------------------------------------\n";
        std::cout << "[TLS Worker " << workerId << "] from "
                  << pkt.remoteIp << ":" << pkt.remotePort << "\n";
        std::cout << sanitizeSipForLog(pkt.data, MAX_LOG_DATA_LENGTH) << "\n";
    }

    SipMessage msg;
    if (!parseSipMessage(pkt.data, msg))
    {
        Logger::instance().info("[TlsServer] Malformed SIP message dropped from "
            + pkt.remoteIp + ":" + std::to_string(pkt.remotePort));
        return;
    }

    std::string response;
    if (msg.type == SipType::Request)
    {
        if (sipCore_.handlePacket(pkt, msg, response) && !response.empty())
        {
            if (!sendTo(pkt.remoteIp, pkt.remotePort, response))
            {
                Logger::instance().error("[TlsServer] Failed to send SIP response");
            }
        }
    }
    else
    {
        sipCore_.handleResponse(pkt, msg);
    }
}

bool TlsServer::sendTo(const std::string& ip, uint16_t port, const std::string& data)
{
    if (data.empty())
    {
        return false;
    }

    int fd = findOrCreateConnection(ip, port);
    if (fd < 0)
    {
        Logger::instance().error("[TlsServer] Cannot send to " + ip + ":" + std::to_string(port)
            + " (no TLS connection)");
        return false;
    }

    std::shared_ptr<TlsConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connMutex_);
        auto it = connections_.find(fd);
        if (it == connections_.end())
        {
            return false;
        }
        conn = it->second;
    }

    const char* ptr = data.c_str();
    std::size_t remaining = data.size();
    bool sendFailed = false;
    {
        std::lock_guard<std::mutex> ioLock(conn->ioMutex);
        while (remaining > 0)
        {
            int sent = SSL_write(conn->ssl, ptr, static_cast<int>(remaining));
            if (sent <= 0)
            {
                int sslErr = SSL_get_error(conn->ssl, sent);
                if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                logSslError("[TlsServer] SSL_write failed");
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
