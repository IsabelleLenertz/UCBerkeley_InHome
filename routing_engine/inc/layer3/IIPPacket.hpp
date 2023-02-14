#ifndef INC_IIPPACKET_HPP_
#define INC_IIPPACKET_HPP_

#include <cstdint>

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
    virtual int GetIPVersion() = 0;
    
    /// <summary>
    /// Constructs a Packet object from raw
    /// packet data
    /// </summary>
    /// <param name="buff">Raw data buffer</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <returns>
    /// Error Code:
    ///   0: No Error
    ///   Other error codes depend on subclass
    /// <remarks>
    /// Data must be in network byte order
    /// </remarks>
    virtual int Deserialize(const uint8_t *buff, uint16_t len) = 0;
    
    /// <summary>
    /// Constructs raw Packet data from the
    /// Packet object
    /// </summary>
    /// <param name="buff">Output data buffer</param>
    /// <param name="len">
    ///   As an input: Maximum length of buff, in bytes
    ///   As an output: Actual length of constructed
    ///      packet, in bytes
    /// </param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    ///   Other error codes depend on subclass
    /// <remarks>
    /// Data buffer output is in network byte order
    /// If the return value is non-zero, then the
    /// contents of the output buffer are undefined
    /// </returns>
    virtual int Serialize(uint8_t* buff, uint16_t& len) = 0;
};

#endif
