#ifndef _INC_IPPACKETFACTORY_HPP_
#define _INC_IPPACKETFACTORY_HPP_

#include "layer3/IPv4Packet.hpp"
// #include "layer3/IPv6Packet.hpp"

class IPPacketFactory
{
public:
    static IIPPacket* BuildPacket(const uint8_t *buff, uint16_t len);
};

#endif
