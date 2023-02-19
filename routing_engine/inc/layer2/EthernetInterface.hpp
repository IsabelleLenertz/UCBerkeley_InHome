#ifndef INC_ETHERNETINTERFACE_HPP_
#define INC_ETHERNETINTERFACE_HPP_

#include "layer2/ILayer2Interface.hpp"
#include "arp/ARPMessage.hpp"
#include "arp/IARPTable.hpp"

#include <pcap/pcap.h>
#include <thread>
#include <string>
#include <mutex>

/// <summary>
/// Concrete implementation of ILayer2Interface
/// for Ethernet interfaces
/// </summary>
class EthernetInterface : public ILayer2Interface
{
public:
    EthernetInterface(const char *if_name, IARPTable *arp_table);
    ~EthernetInterface();
    
    int Open();
    int Close();
    
    int Listen(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener, bool async);
    int StopListen();
    
    int SendPacket(const struct sockaddr &l3_local_addr, const struct sockaddr &l3_dest_addr, const uint8_t *data, size_t len);
    
    const char *GetName();
    
    void SetMACAddress(const struct ether_addr& mac_addr);
    
    void SetIPAddressQueryMethod(IPOwnershipQuery method);
    
    static constexpr struct ether_addr BROADCAST_MAC {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static constexpr struct ether_addr BLANK_MAC {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    static const size_t MAX_FRAME_LEN = 1500;

private:
    char error_buffer[PCAP_ERRBUF_SIZE];
    std::string _if_name;
    Layer2ReceiveCallback _callback;
    NewARPEntryListener _arp_listener;
    IPOwnershipQuery _owns_address;
    pcap_t *_handle;
    std::thread _thread;
    IARPTable *_arp_table;
    struct ether_addr _mac_addr;
    uint8_t _frame_buffer[MAX_FRAME_LEN];
    
    std::mutex _mutex;
    
    const int32_t TIMEOUT_MS = 10000;
    
    /// <summary>
    /// Static function used as receive callback to pcap_loop.
    /// Processes an incoming packet.
    /// </summary>
    /// <param name="user">Pointer to EthernetInterface object</param>
    /// <param name="h">PCAP header containing metadata</param>
    /// <param name="bytes">Packet data</param>
    static void _receive(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
    
    /// <summary>
    /// Handles an incoming ARP packet.
    /// </summary>
    /// <param name="h">PCAP header containing metadata</param>
    /// <param name="bytes">Packet data</param>
    void _handle_arp(const struct pcap_pkthdr *h, const u_char *bytes);
    
    /// <summary>
    /// Handles an incoming ARP request.
    /// </summary>
    /// <param name="arp_msg">Deserialized ARP message</param>
    void _handle_arp_reply(ARPMessage &arp_msg);
    
    /// <summary>
    /// Handles an incoming ARP request.
    /// </summary>
    /// <param name="arp_msg">Deserialized ARP message</param>
    void _handle_arp_request(ARPMessage &arp_msg);
    
    /// <summary>
    /// Given an ARP request, constructs an ARP reply to that request
    /// </summary>
    /// <param name="request">ARP request</param>
    /// <param name="reply">ARP reply out</param>
    /// <remarks>
    /// This method assumes that the request is not malformed.
    /// Providing a malformed request results in undefined behavior.
    /// An example of a malformed request is one in which one or more
    /// address formats does not match the specified HW or Protocol
    /// address types spcified.
    /// If the request was succesfully deserialized from binary
    /// and not modified further, it will be a valid request.
    /// </remarks>
    void _build_arp_reply(ARPMessage &request, ARPMessage &reply);
    
    /// <summary>
    /// Handles an incoming IP packet.
    /// Passes packet up to layer 3.
    /// </summary>
    /// <param name="h">PCAP header containing metadata</param>
    /// <param name="bytes">Packet data</param>
    void _handle_ip(const struct pcap_pkthdr *h, const u_char *bytes);
    
    /// <summary>
    /// Executes the capture loop.
    /// </summary>
    void _captureLoop();
    
    /// <summary>
    /// Calculates the CRC of the provided
    /// data, given length in bytes
    /// </summary>
    /// <param name="data">Source data</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <param name="crc">CRC output</param>
    /// <remarks>
    /// CRC output is in network byte order
    /// </remarks>
    void _calcCRC(uint8_t *data, size_t len, uint8_t *crc);
};

#endif
