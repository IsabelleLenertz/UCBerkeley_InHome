#ifndef INC_ETHERNETINTERFACE_HPP_
#define INC_ETHERNETINTERFACE_HPP_

#include "layer2/ILayer2Interface.hpp"
#include "arp/IARPTable.hpp"

#include <pcap/pcap.h>
#include <thread>
#include <string>

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
    
    int Listen(Layer2ReceiveCallback callback, bool async);
    int StopListen();
    
    int SendPacket(const in_addr_t &l3_src_addr, const in_addr_t &l3_dest_addr, const uint8_t *data, size_t len);
    
    const char *GetName();

private:
    char error_buffer[PCAP_ERRBUF_SIZE];
    std::string _if_name;
    Layer2ReceiveCallback _callback;
    pcap_t *_handle;
    std::thread _thread;
    IARPTable *_arp_table;
    
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
