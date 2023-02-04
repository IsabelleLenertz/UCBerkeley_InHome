#include "layer2/EthernetInterface.hpp"

#include <net/ethernet.h>

EthernetInterface::EthernetInterface(const char *if_name, IARPTable *arp_table)
    : _handle(nullptr),
      _thread(),
      _arp_table(arp_table)
{
    _if_name = std::string(if_name);
}

EthernetInterface::~EthernetInterface()
{
    this->Close();
}

int EthernetInterface::Open()
{
    _handle = pcap_open_live(
        _if_name.c_str(), // Interface to open
        BUFSIZ,           // Maximum number of bytes per packet
        0,                // Not in promiscuous mode
        TIMEOUT_MS,       // Packet buffer timeout
        error_buffer);    // Error output buffer
    
    if (_handle == nullptr)
    {
        return 1; // Could not open interface
    }
    
    return 0;
}

int EthernetInterface::Close()
{
    // If still listening, stop
    this->StopListen();
    
    // Close the handle
    pcap_close(_handle);
    
    return 0;
}

int EthernetInterface::Listen(Layer2ReceiveCallback& callback, bool async)
{
    // Register the callback
    this->_callback = callback;
    
    if (async)
    {
        // If async, start up a thread on which
        // to call the capture loop
        _thread = std::thread(std::bind(&EthernetInterface::captureLoop, this));
    }
    else
    {
        // If not async, capture on current thread
        this->captureLoop();
    }
    
    return 0;
}

int EthernetInterface::StopListen()
{
    // Check if the thread is running
    if (_thread.joinable())
    {
        // Force thread termination
        pcap_breakloop(_handle);
        
        // Wait for thread to complete
        _thread.join();
    }
}

int EthernetInterface::SendPacket(const in_addr_t &l3_src_addr, const in_addr_t &l3_dest_addr, const uint8_t *data, size_t len)
{
    return 0;
}

void EthernetInterface::captureLoop()
{
    pcap_loop(
        _handle,                        // Handle to interface
        0,                              // Max packets to capture
        &EthernetInterface::_receive,   // Callback
        (u_char*)this);                 // This object
}

///////////////////////////////////
//////// Private Functions ////////
///////////////////////////////////

void EthernetInterface::_receive(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    // Cast user variable to pointer to ethernet interface object
    EthernetInterface *_this = (EthernetInterface*)user;
    
    struct ether_header *eth_header;
    switch (ntohs(eth_header->ether_type))
    {
        case ETHERTYPE_ARP:
        {
            _this->_handle_arp(h, bytes);
            break;
        }
        case ETHERTYPE_IP:
        {
            _this->_handle_ip(h, bytes);
            break;
        }
        default:
        {
            // Other types not supported. Discard.
            break;
        }
    }
}

void EthernetInterface::_handle_ip(const struct pcap_pkthdr *h, const u_char *bytes)
{
    // Extract Layer 3 packet
    const uint8_t *l3_pkt;
    size_t l3_pkt_len;
    
    // Offset by size of ethernet header
    l3_pkt = bytes + ETHER_HDR_LEN;
    
    // Get size of L3 packet
    // Size of ethernet frame minus size of
    // header and trailer
    l3_pkt_len = h->len - (ETHER_HDR_LEN + ETHER_CRC_LEN);
    
    // Execute callback
    this->_callback(l3_pkt, l3_pkt_len);
}

void EthernetInterface::_handle_arp(const struct pcap_pkthdr *h, const u_char *bytes)
{
    // TODO
}
