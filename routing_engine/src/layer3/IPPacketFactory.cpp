#include "layer3/IPPacketFactory.hpp"

IIPPacket* IPPacketFactory::BuildPacket(const uint8_t *buff, uint16_t len)
{
    // Minimum 1 byte required to get IP version
    if (len < 1)
    {
        return nullptr;
    }
    
    // Extract IP version
    uint8_t ip_version = (*buff) >> 4;

    // Construct appropriate packet object
    // based on IP version
    IIPPacket *result = nullptr;
    switch (ip_version)
    {
        case 4:
        {
            // IPv4
            result = (IIPPacket*)new IPv4Packet();
            break;
        }
        case 6:
        {
            // IPv6: Not yet supported
            result = nullptr;
            break;
        }
        default:
        {
            result = nullptr;
            break;
        }
    }
    
    return result;
}