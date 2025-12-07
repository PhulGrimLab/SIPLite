#include "UdpServer.h"
#include "UdpPacket.h"

#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <thread>

std::atomic<bool> g_terminate(false);

void signalHandler(int signo) 
{
    if (signo == SIGINT) 
    {
        std::cout << "\n[Main] SIGINT received\n";
        g_terminate = true;
    }
}

int main() 
{
    std::signal(SIGINT, signalHandler);

    UdpServer server;
    const std::string bindIp = "0.0.0.0";
    const uint16_t bindPort = 5060;
    const std::size_t workerCount = 4;   // 워커 스레드 수

    if (!server.start(bindIp, bindPort, workerCount)) 
    {
        std::cerr << "[Main] 서버 시작 실패\n";
        return 1;
    }

    std::cout << "[Main] UDP 서버 실행 중. Ctrl+C 로 종료\n";

    while (!g_terminate) 
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    server.stop();
    return 0;
}
