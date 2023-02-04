#ifndef INC_ARPMESSAGE_HPP_
#define INC_ARPMESSAGE_HPP_

#include <cstdint>
#include <cstring>

typedef enum
{
    ARP_HW_TYPE_ETHERNET    = 1,  // Ethernet
    ARP_HW_TYPE_IEEE_802    = 6,  // IEEE 802 Networks
    ARP_HW_TYPE_ARCNET      = 7,  // ARCNET
    ARP_HW_TYPE_FR_RELAY    = 15, // Frame Relay
    ARP_HW_TYPE_ATM16       = 16, // Asynchronous Transfer Mode
    ARP_HW_TYPE_HDLC        = 17, // HDLC
    ARP_HW_TYPE_FIBER       = 18, // Fiber Channel
    ARP_HW_TYPE_ATM19       = 19, // Asynchronous Transfer Mode
    ARP_HW_TYPE_SERIAL      = 20, // Serial Line
} arp_hw_type_t;

typedef enum
{
    ARP_PROTO_TYPE_IPV4 = 0x0800, // Internet Protocol Version 4
    ARP_PROTO_TYPE_IPV6 = 0x86DD, // Internet Protocol Version 6
} arp_proto_type_t;

typedef enum
{
    ARP_MSG_TYPE_REQUEST    = 1, // ARP Request
    ARP_MSG_TYPE_REPLY      = 2, // ARP Reply
    ARP_MSG_TYPE_RREQUEST   = 3, // RARP Request
    ARP_MSG_TYPE_RREPLY     = 4, // RARP Reply
    ARP_MSG_TYPE_DREQUEST   = 5, // DRARP Request
    ARP_MSG_TYPE_DREPLY     = 6, // DRARP Reply
    ARP_MSG_TYPE_DERROR     = 7, // DRARP Error
    ARP_MSG_TYPE_IREQUEST   = 8, // InARP Request
    ARP_MSG_TYPE_IREPLY     = 9, // InARP Reply
} arp_msg_type_t;

class ARPMessage
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    ARPMessage();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~ARPMessage();
    
    /// <summary>
    /// Deserializes an ARP message
    /// </summary>
    /// <param name="data">Input data</param>
    /// <param name="len"> Length of input data, in bytes</param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    ///   1: Overflow error
    /// </returns>
    /// <remarks>Data must be in host byte order</remarks>
    int Deserialize(const uint8_t *data, size_t len);
    
    /// <summary>
    /// Serializes an ARP message
    /// </summary>
    /// <param name="data">Output data buffer</param>
    /// <param name="len">
    ///   Input: Maximum length of data buffer in, in bytes
    ///   Output: Actual size of message, in bytes
    /// </param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    ///   1: Overflow error : Buffer is too small for output
    ///   2: Undefined Address: One or more addresses is not defined
    /// </returns>
    /// <remarks>Data output is in host byte order</remarks>
    int Serialize(uint8_t *buff, size_t &len);
    
    /// <summary>
    /// Returns the hardware type in this message
    /// </summary>
    /// <returns>Hardware type</returns>
    arp_hw_type_t GetHWType();
    
    /// <summary>
    /// Sets the hardware type in this message
    /// </summary>
    /// <param name="hw_type">Hardware type</param>
    void SetHWType(arp_hw_type_t hw_type);
    
    /// <summary>
    /// Returns the protocol type in this message
    /// </summary>
    /// <returns>Protocol type</returns>
    arp_proto_type_t GetProtocolType();
    
    /// <summary>
    /// Sets the protocol type in this message
    /// </summary>
    /// <param name="p_type">Protocol type</param>
    void SetProtocolType(arp_proto_type_t p_type);
    
    /// <summary>
    /// Returns the length of the hardware
    /// addresses in this message, in bytes
    /// </summary>
    /// <returns>HW address length, in bytes</returns>
    uint8_t GetHWAddrLen();
    
    /// <summary>
    /// Sets the length of the hardware
    /// address in this message, in bytes
    /// </summary>
    /// <param name="len">HW address length, in bytes</param>
    void SetHWAddrLen(uint8_t len);
    
    /// <summary>
    /// Returns the length of the protocol
    /// addresses in this message, in bytes
    /// </summary>
    /// <returns>Protocol address length, in bytes</returns>
    uint8_t GetProtoAddrLen();
    
    /// <summary>
    /// Sets the length of the protocol
    /// addresses in this message, in bytes
    /// </summary>
    /// <param name="len">Protocol address length, in bytes</param>
    void SetProtoAddrLen(uint8_t len);
    
    /// <summary>
    /// Returns the message type (OpCode) of this message
    /// </summary>
    /// <returns>Message Type</returns>
    arp_msg_type_t GetMessageType();
    
    /// <summary>
    /// Sets the message type (OpCode) of this message
    /// </summary>
    /// <param name="type">Message Type</param>
    void SetMessageType(arp_msg_type_t type);
    
    /// <summary>
    /// Returns a pointer to the sender HW address
    /// </summary>
    /// <returns>Pointer to first byte of HW address</returns>
    /// <remarks>Use GetHWAddrLen to get length of address</remarks>
    uint8_t *GetSenderHWAddr();
    
    /// <summary>
    /// Sets the sender HW address.
    /// Also sets the length of the HW addresses.
    /// </summary>
    /// <param name="addr">Pointer to address</param>
    /// <param name="len">Length of address, in bytes</param>
    /// <remarks>
    /// Make sure that the length of both hardware addresses
    /// are the same. Otherwise, overflow may occur
    /// upon serialization
    /// </remarks>
    void SetSenderHWAddress(uint8_t *addr, uint8_t len);
    
    /// <summary>
    /// Returns a pointer to the sender protocol address
    /// </summary>
    /// <returns>Pointer to first byte of protocol address</returns>
    /// <remarks>Use GetProtoAddrLen to get length of address</remarks>
    uint8_t *GetSenderProtoAddress();
    
    /// <summary>
    /// Sets the sender protocol address.
    /// Also sets the length of the protocol addresses.
    /// </summary>
    /// <param name="addr">Pointer to address</param>
    /// <param name="len">Length of address, in bytes</param>
    /// <remarks>
    /// Make sure that the length of both protocol addresses
    /// are the same. Otherwise, overflow may occur
    /// upon serialization
    /// </remarks>
    void SetSenderProtoAddress(uint8_t *addr, uint8_t len);
    
    /// <summary>
    /// Returns a pointer to the target HW address
    /// </summary>
    /// <returns>Pointer to first byte of HW addres</returns>
    /// <remarks>Use GetHWAddrLen to get length of address</remarks>
    uint8_t *GetTargetHWAddress();
    
    /// <summary>
    /// Sets the target target HW address
    /// Also sets the length of the HW addresses.
    /// </summary>
    /// <param name="addr">Pointer to address</param>
    /// <param name="len">Length of address, in bytes</param>
    /// <remarks>
    /// Make sure that the length of both hardware addresses
    /// are the same. Otherwise, overflow may occur
    /// upon serialization
    /// </remarks>
    void SetTargetHWAddress(uint8_t *addr, uint8_t len);
    
    /// <summary>
    /// Returns a pointer to the target protocol address
    /// </summary>
    /// <returns>Pointer to first byte of protocol address</returns>
    /// <remarks>Use GetProtoAddrLen to get length of address</remarks>
    uint8_t *GetTargetProtoAddress();
    
    /// <summary>
    /// Sets the target protocol address.
    /// Also sets the length of the protocol addresses.
    /// </summary>
    /// <param name="addr">Pointer to address</param>
    /// <param name="len">Length of address, in bytes</param>
    /// <remarks>
    /// Make sure that the length of both protocol addresses
    /// are the same. Otherwise, overflow may occur
    /// upon serialization
    /// </remarks>
    void SetTargetProtoAddress(uint8_t *addr, uint8_t len);

private:
    arp_hw_type_t _hw_type;
    arp_proto_type_t _proto_type;
    arp_msg_type_t _msg_type;
    
    uint8_t _hw_addr_len;
    uint8_t _proto_addr_len;
    
    uint8_t *_src_hw_addr;
    uint8_t *_src_proto_addr;
    uint8_t *_targ_hw_addr;
    uint8_t *_targ_proto_addr;
    
    const int MIN_SIZE_BYTES = 8;
};

#endif