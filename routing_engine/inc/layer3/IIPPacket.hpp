#ifndef INC_IIPPACKET_HPP_
#define INC_IIPPACKET_HPP_

#include <cstdint>
#include <cstdlib>

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
    
    /// <summary>
    /// Gets the layer 4 protocol number.
    /// </summary>
    /// <returns>Layer 4 protocol number</returns>
    virtual uint8_t GetProtocol() = 0;

    /// <summary>
    /// Gets the data payload
    /// </summary>
    /// <param name="data_out">Pointer to data</param>
    /// <returns>Length of data, in bytes</returns>
    virtual size_t GetData(const uint8_t* &data_out) = 0;

    /// <summary>
    /// Sets the data payload
    /// </summary>
    /// <param name="data">Data</param>
    /// <param name="len">Length of data, in bytes</param>
    virtual void SetData(const uint8_t* data, size_t len) = 0;

    /// <summary>
    /// Returns a reference to a sockaddr object which
    /// stores the source address of this packet
    /// </summary>
    /// <returns>Source Address</returns>
    virtual const struct sockaddr& GetSourceAddress() = 0;
    
    /// <summary>
    /// Returns a reference to a sockaddr object which
    /// stores the destination address of this packet
    /// </summary>
    /// <returns>Destination Address</returns>
    virtual const struct sockaddr& GetDestinationAddress() = 0;
    
    /// <summary>
    /// Sets the source address for this packet
    /// </summary>
    /// <param name="addr">Source address</param>
    virtual void SetSourceAddress(const struct sockaddr& addr) = 0;
    
    /// <summary>
    /// Sets the destination address for this packet
    /// </summary>
    /// <param name="addr">Destination address</param>
    virtual void SetDestinationAddress(const struct sockaddr& addr) = 0;

    /// <summary>
    /// Gets a flag indicating whether this packet was
    /// received on the default interface (that is, the
    /// default interface is the ingress interface)
    /// </summary>
    /// <returns>True if from default interface</returns>
    /// <remarks>
    /// Some access control decisions are based on whether
    /// a packet is destined for or arrived from the internet
    /// </remarks>
    virtual bool GetIsFromDefaultInterface() = 0;

    /// <summary>
    /// Gets a flag indicating whether this packet is
    /// destined for the default interface (that is, the
    /// default interface is the egress interface)
    /// </summary>
    /// <returns>True if going to default interface</returns>
    virtual bool GetIsToDefaultInterface() = 0;

    /// <summary>
    /// Sets a flag indicating whether this packet was
    /// received on the default interface (that is, the
    /// default interface is the ingress interface)
    /// </summary>
    /// <param name="flag">True if from default interface</param>
    virtual void SetIsFromDefaultInterface(bool flag) = 0;

    /// <summary>
    /// Sets a flag indicating whether this packet is
    /// destined for the default interface (that is, the
    /// default interface is the egress interface)
    /// </summary>
    /// <param name="flag">True if from default interface</param>
    virtual void SetIsToDefaultInterface(bool flag) = 0;
};

#endif
