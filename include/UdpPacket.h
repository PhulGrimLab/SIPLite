#pragma once

#include <string>
#include <cstdint>

// 전송 프로토콜 타입
enum class TransportType { UDP, TCP, TLS };

struct UdpPacket 
{
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string data;
    TransportType transport = TransportType::UDP;  // 수신 프로토콜 (기본: UDP)
};
