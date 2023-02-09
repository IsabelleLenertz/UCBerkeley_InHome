#ifndef INC_IIPPACKET_HPP_
#define INC_IIPPACKET_HPP_

class IIPPacket
{
public:
    /// <summary>
    /// Returns the IP Version
    /// of this packet
    /// </summary>
    /// <returns>
    /// IP Version
    ///   4: IPv4
    ///   6: IPv6
    /// </returns>
    int GetIPVersion();
};

#endif