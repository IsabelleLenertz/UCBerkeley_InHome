#include "layer2/EthernetInterface.hpp"

#include <net/ethernet.h>
#include <cstring>
#include <arpa/inet.h>

#include <iostream>

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
    if (_handle != nullptr)
    {
        pcap_close(_handle);
    }
    
    return 0;
}

int EthernetInterface::Listen(Layer2ReceiveCallback callback, bool async)
{
    // Register the callback
    this->_callback = callback;
    
    if (async)
    {
        // If async, start up a thread on which
        // to call the capture loop
        _thread = std::thread(std::bind(&EthernetInterface::_captureLoop, this));
    }
    else
    {
        // If not async, capture on current thread
        this->_captureLoop();
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
    
    return 0;
}

int EthernetInterface::SendPacket(const in_addr_t &l3_src_addr, const in_addr_t &l3_dest_addr, const uint8_t *data, size_t len)
{
    int status = -1;
    int frame_len = len + ETHER_HDR_LEN + ETHER_CRC_LEN;
    
    // Get Addresses from ARP table
    bool hit;
    struct ether_addr l2_src_addr, l2_dest_addr;
    
    _arp_table->GetL2Address(l3_src_addr, l2_src_addr);
    
    hit = _arp_table->GetL2Address(l3_dest_addr, l2_dest_addr);
    
    if (!hit)
    {
        // ARP Table Miss
        // TODO Execute ARP
        status = 1;
    }
    else
    {
        // ARP Table Hit
        uint8_t frame_buff[frame_len];
        
        // Populate header
        struct ether_header *eth_header = (struct ether_header*)frame_buff;
        memcpy(eth_header->ether_dhost, &l2_dest_addr, sizeof(ether_addr));
        memcpy(eth_header->ether_shost, &l2_src_addr, sizeof(ether_addr));
        eth_header->ether_type = htons(ETHERTYPE_IP);
        
        // Copy payload
        memcpy(frame_buff + ETHER_HDR_LEN, data, len);
        
        // Calculate CRC
        _calcCRC(frame_buff, (size_t)(ETHER_HDR_LEN + len), frame_buff + ETHER_HDR_LEN + len);
        
        int bytes_written = pcap_inject(_handle, frame_buff, frame_len);
        
        if (bytes_written <= 0)
        {
            status = 2;
        }
        else
        {
            status = 0;
        }
    }

    return status;
}

void EthernetInterface::_captureLoop()
{
    std::cout << "This pointer at: " << std::hex << (uintptr_t)this << std::endl;

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
    
    std::cout << "Data Received" << std::endl;
    std::cout << "This pointer at: " << std::hex << (uintptr_t)user << std::endl;
    
    struct ether_header *eth_header = (struct ether_header*)bytes;
    switch (ntohs(eth_header->ether_type))
    {
        case ETHERTYPE_ARP:
        {
            _this->_handle_arp(h, bytes);
            break;
        }
        case ETHERTYPE_IP:
        {
            std::cout << "IP Packet Received" << std::endl;
        
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

const char *EthernetInterface::GetName()
{
    return _if_name.c_str();
}

void EthernetInterface::_calcCRC(uint8_t *data, size_t len, uint8_t *crc)
{
    static const uint32_t poly = 0xEDB88320;
    uint32_t *_crc = (uint32_t*)crc;
    
    *_crc = 0xFFFFFFFF;
    
    int i, j;
    for (i = 0; i < len; i++)
    {
        char ch = data[i];
        for (j = 0; j < 8; j++)
        {
            uint32_t b = (ch^*_crc) & 1;
            *_crc >>= 1;
            if (b)
            {
                *_crc = *_crc ^ poly;
            }
            ch >>= 1;
        }
    }
    
    // Invert CRC
    *_crc = ~*_crc;
    
    // Convert host to network byte order
    *_crc = htonl(*_crc);
}
