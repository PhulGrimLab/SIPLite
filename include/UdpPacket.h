#pragma once

#include <string>
#include <cstdint>

struct UdpPacket 
{
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string data;
};
