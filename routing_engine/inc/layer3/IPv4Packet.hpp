#ifndef IPV4_PACKET_H_
#define IPV4_PACKET_H_

#include "layer3/IIPPacket.hpp"
#include "IPv4Option.hpp"

#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>

// Error Definitions
#define IPV4_PACKET_SUCCESS                0
#define IPV4_PACKET_ERROR_OVERFLOW         1
#define IPV4_PACKET_ERROR_INVALID_CHECKSUM 2
#define IPV4_PACKET_ERROR_UNDEFINED_OPTION 3
#define IPV4_PACKET_ERROR_INVALID_VERSION  4

/// <summary>
/// Encapsulates IPv4 Data. Provides methods
/// to serialize, deserialize, and manipulate
/// encapsulated data.
/// </summary>
class IPv4Packet : public IIPPacket
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    IPv4Packet();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~IPv4Packet();
    
    int GetIPVersion();
    
    /// <summary>
    /// Constructs an IPv4 Packet object from raw
    /// IPv4 Packet data
    /// </summary>
    /// <param name="buff">Raw data buffer</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <returns>
    /// Error Code:
    ///   IPV4_PACKET_SUCCESS
    ///   IPV4_PACKET_ERROR_OVERFLOW
    ///   IPV4_PACKET_ERROR_INVALID_CHECKSUM
    ///   IPV4_PACKET_ERROR_UNDEFINED_OPTION
    /// <remarks>
    /// Data must be in network byte order
    /// </remarks>
    int Deserialize(const uint8_t *buff, uint16_t len);
    
    /// <summary>
    /// Constructs raw IPv4 Packet data from the
    /// IPv4 Packet object
    /// </summary>
    /// <param name="buff">Output data buffer</param>
    /// <param name="len">
    ///   As an input: Maximum length of buff, in bytes
    ///   As an output: Actual length of constructed
    ///      packet, in bytes
    /// </param>
    /// <returns>
    /// Error Code:
    ///   IPV4_PACKET_SUCCESS
    ///   IPV4_PACKET_ERROR_OVERFLOW
    /// <remarks>
    /// Data buffer output is in network byte order
    /// If the return value is non-zero, then the
    /// contents of the output buffer are undefined
    /// </returns>
    int Serialize(uint8_t* buff, uint16_t& len);
    
    /// <summary>
    /// Returns the calculated size of the header,
    /// in bytes, based on currently set fields
    /// </summary>
    /// <returns>Header length, in bytes</returns>
    /// <remarks>
    /// This is distinct from the value of the header
    /// length field for two reasons:
    /// 1. This function dynamically calculates the
    /// value based on currently set fields. The
    /// header length field is only set upon
    /// serialization of the packet.
    /// 2. The header length field is in units of
    /// 32-bit words, this function returns bytes.
    /// </remarks>
    uint8_t GetHeaderLengthBytes();
    
    /// <summary>
    /// Returns the calculated total size of the
    /// full packet, in bytes, based on currently
    /// set fields
    /// </summary>
    /// <returns>Total packet length, in bytes</returns>
    /// <remarks>
    /// This is distinct from the value of the total
    /// length field because this value is based
    /// on currently set fields. The total length
    /// field is only set upon serialization of
    /// the packet.
    /// </remarks>
    uint16_t GetTotalLengthBytes();
    
    /// <summary>
    /// Gets the current value of the Type of Service (ToS)
    /// field
    /// </summary>
    /// <returns>4-bit TOS value, as a uint8_t</returns>
    /// <remarks>
    /// Relevant bits are 4 least-significant bits
    /// 4 most-significant bits are set to 0
    /// </remarks>
    uint8_t GetTOS();
    
    /// <summary>
    /// Sets the value of the Type of Server (ToS) field
    /// </summary>
    /// <param name="tos">4-bit value to set</param>
    /// <remarks>
    /// Relevant bits are 4 least-significant bits
    /// 4 most-significant bits are ignored.
    /// </remarks>
    void SetTOS(uint8_t tos);
    
    /// <summary>
    /// Gets the 16-bit Stream ID
    /// </summary>
    /// <returns>16-bit Stream ID</returns>
    /// <remarks>
    /// Returned value is in native byte order
    /// </remarks>
    uint16_t GetStreamID();
    
    /// <summary>
    /// Sets the 16-bit Stream ID
    /// </summary>
    /// <param name="sid">Value to set</param>
    /// <remarks>
    /// Value must be provided in native byte order
    /// </remarks>
    void SetStreamID(uint16_t sid);
    
    /// <summary>
    /// Gets the Don't Fragment (DF) flag
    /// </summary>
    /// <returns>True if DF flag is 1</returns>
    bool GetDontFragment();
    
    /// <summary>
    /// Sets the value of the DF flag
    /// </summary>
    /// <param name="df">Value to set</param>
    void SetDontFragment(bool df);
    
    /// <summary>
    /// Gets the More Fragments (MF) flag
    /// </summary>
    /// <returns>True if the MF flag is 1</returns>
    bool GetMoreFragments();
    
    /// <summary>
    /// Sets the value of the MF flag
    /// </summary>
    /// <param name="mf">Value to set</param>
    void SetMoreFragments(bool mf);
    
    /// <summary>
    /// Gets the fragment offset
    /// </summary>
    /// <returns>Fragment offset</returns>
    /// <remarks>
    /// Returned value is native byte order
    /// </remarks>
    uint16_t GetFragmentOffset();
    
    /// <summary>
    /// Sets the fragment offset
    /// </summary>
    /// <param name="offset">Value to set</param>
    /// <remarks>
    /// Value must be in native byte order
    /// </remarks>
    void SetFragmentOffset(uint16_t offset);
    
    /// <summary>
    /// Gets the Time-to-Live (TTL)
    /// </summary>
    /// <returns>
    /// TTL, in router hops
    /// </returns>
    uint8_t GetTTL();
    
    /// <summary>
    /// Sets the Time-to-Live (TTL)
    /// </summary>
    /// <param name="ttl">TTL, in router hops</param>
    void SetTTL(uint8_t ttl);
    
    /// <summary>
    /// Gets the protocol number
    /// </summary>
    /// <returns>
    /// Protocol number
    /// </returns>
    uint8_t GetProtocol();
    
    /// <summary>
    /// Sets the protocol number
    /// </summary>
    /// <param name="proto">Protocol number</param>
    void SetProtocol(uint8_t proto);
    
    /// <summary>
    /// Returns a reference to a sockaddr object which
    /// stores the source address of this packet
    /// </summary>
    /// <returns>Source Address</returns>
    const struct sockaddr& GetSourceAddress();
    
    /// <summary>
    /// Sets the source address for this packet
    /// </summary>
    /// <param name="sockaddr">Sets the source address</param>
    void SetSourceAddress(const struct sockaddr& addr);
    
    /// <summary>
    /// Gets the destination IP address
    /// </summary>
    /// <returns>Destination IP</returns>
    /// <remarks>
    /// Result is in network byte order
    /// </remarks>
    const struct sockaddr& GetDestinationAddress();
    
    /// <summary>
    /// Sets the destination address for this packet
    /// </summary>
    /// <param name="addr">Destination address</param>
    void SetDestinationAddress(const struct sockaddr& addr);
    
    // Options
    
    /// <summary>
    /// Returns the option object with the specified
    /// option type
    /// </summary>
    /// <param name="option_type">Option type</param>
    /// <returns>
    /// Pointer to IPv4Option object with matching type
    /// </returns>
    /// <remarks>
    /// Returns nullptr if no such option exists
    /// </remarks>
    IPv4Option* GetOption(uint8_t option_type);
    
    /// <summary>
    /// Sets the option entry for the specified option type
    /// </summary>
    /// <param name="option_type">Option Type</param>
    /// <param name="len">Length of data portion in bytes</param>
    /// <param name="data_in">Data portion</param>
    /// <remarks>
    /// If the specified option_type already exists, updates entry
    /// otherwise, a new entry is created
    /// Note that the length input does not include option type
    /// and length bytes, unlike with the raw option data
    /// </remarks>
    void SetOption(uint8_t option_type, uint8_t len, uint8_t* data_in);
    
    /// <summary>
    /// Removes the option entry for the specified option type
    /// </summary>
    /// <param name="option_type">Option Type</param>
    /// <remarks>
    /// If the specified option_type does not exist, this function
    /// has no effect
    /// </remarks>
    void RemoveOption(uint8_t option_type);
    
    /// <summary>
    /// Sets the data payload
    /// </summary>
    /// <param name="data_in">Pointer to data</param>
    /// <param name="len">Length of data, in bytes</param>
    void SetData(uint8_t *data_in, uint16_t len);
    
    /// <summary>
    /// Gets the data payload
    /// </summary>
    /// <param name="data_out">Pointer to data</param>
    /// <returns>Length of data, in bytes</returns>
    uint16_t GetData(const uint8_t* &data_out);
    
    /// <summary>
    /// Calculates the header checksum for the specified
    /// data buffer
    /// </summary>
    /// <param name="buff">Input data buffer</param>
    /// <param name="header_len">Header length, in bytes</param>
    /// <returns>16-bit checksum</returns>
    static uint16_t CalcHeaderChecksum(const uint8_t *buff, size_t header_len);

private:
    uint8_t _tos;
    
    uint16_t _stream_id;
    bool _dont_fragment;
    bool _more_fragments;
    uint16_t _fragment_offset;
    
    uint8_t _ttl;
    uint8_t _protocol;
    
    struct sockaddr_in _src_addr;
    struct sockaddr_in _dest_addr;
    
    std::vector<IPv4Option> _options;
    std::vector<uint8_t> _data;
    
    const int MIN_HEADER_SIZE_BYTES = 20; // 5 words
    const int MAX_HEADER_SIZE_BYTES = 60; // 15 words
};

#endif
