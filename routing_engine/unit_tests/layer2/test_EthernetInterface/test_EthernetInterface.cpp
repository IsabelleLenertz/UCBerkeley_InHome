#include "gtest/gtest.h"
#include "arp/LocalARPTable.hpp"
#include "layer2/EthernetInterface.hpp"
#include "layer3/IPv4Packet.hpp"
#include "pcap/pcap.h"
#include <iostream>
#include <functional>

// Global receive flag
bool data_received = false;

std::mutex _mutex;

std::ostream& print_addr(std::ostream& lhs, const in_addr_t &addr)
{
    uint32_t val = addr;
    
    lhs << std::dec;
    lhs << (val >> 24) << ".";
    val &= 0x00FFFFFF;
    lhs << (val >> 16) << ".";
    val &= 0x0000FFFF;
    lhs << (val >> 8) << ".";
    val &= 0x000000FF;
    lhs << (val);
    
    return lhs;
}

/// <summary>
/// Receive callback for ethernet frames.
/// </summary>
/// <param name="data">Receive data</param>
/// <param name="len">Length of data, in bytes</param>
void receive_callback(const uint8_t *data, size_t len)
{
    IPv4Packet pkt;
    int status = pkt.Deserialize(data, len);
    
    if (status)
    {
        std::cout << "Error deserializing IP packet (" << status << ")" << std::endl;
        return;
    }
    
    in_addr_t l3_addr;
    
    l3_addr = pkt.GetSourceAddress();
    std::cout << "Source Address: ";
    print_addr(std::cout, l3_addr);
    std::cout << std::endl;
    
    l3_addr = pkt.GetDestinationAddress();
    std::cout << "Destination Address: ";
    print_addr(std::cout, l3_addr);
    std::cout << std::endl;
    
    std::scoped_lock lock {_mutex};
    data_received = true;
}

/// <summary>
/// Sends an ethernet frame on an interface
/// and verifies that the frame loops back
/// and is received intact.
/// </summary>
/// <remarks>
/// This test may fail if run without root
/// privileges, as it will be unable to
/// open the interface for capture.
/// </remarks>
TEST(test_EthernetInterface, test_loopback)
{
    // Setup the ARP Table
    // 192.168.0.195
    // TODO This IP address should be retrieved
    // using PCAP
    static const uint8_t IP_REMOTE[4] = {172, 16, 224, 27};
    struct sockaddr l3_addr;
    l3_addr.sa_family = AF_INET;
    memcpy(l3_addr.sa_data, IP_REMOTE, 4);
    
    static const uint8_t IP_LOCAL[4] = {172, 16, 224, 47};
    struct sockaddr l3_addr_local;
    l3_addr_local.sa_family = AF_INET;
    memcpy(l3_addr_local.sa_data, IP_LOCAL, 4);
    
    struct ether_addr l2_addr
    {
        0x08, 0x00, 0x27, 0x7d, 0xcb, 0xa8
    };
    struct ether_addr l2_addr_local
    {
        0x08, 0x00, 0x27, 0xd2, 0xb5, 0x87
    };
    
    LocalARPTable arp_table;
    arp_table.SetARPEntry(l3_addr_local, l2_addr_local); // Set ARP Entry for self
    arp_table.SetARPEntry(l3_addr, l2_addr);

    // Use PCAP to get devices
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    int status;
    
    // Get all devices
    status = pcap_findalldevs(&alldevsp, errbuf);
    ASSERT_EQ(0, status);
    
    // Use first device
    pcap_if_t *dev = alldevsp;
    
    // Build an ethernet interface around
    // the first device
    EthernetInterface eth(dev->name, &arp_table);
    EthernetInterface eth1(dev->next->name, &arp_table);
    
    // Open ethernet interface for live capture
    eth.Open();
    eth1.Open();
    
    // Listen on ethernet interface
    status = eth1.Listen(std::bind(receive_callback, std::placeholders::_1, std::placeholders::_2), true);
    ASSERT_EQ(0, status);
    
    // Define an ethernet frame
    uint8_t payload[36];
    uint8_t l3_payload[16] = {0x80, 0x00, 0x80, 0x00, 0x08, 0x00, 0x00, 0x00,
                           'H', 'E', 'L', 'L', 'O', '!', 0x00, 0x00};
    
    in_addr_t *ip_local = (in_addr_t*)l3_addr_local.sa_data;
    in_addr_t *ip_addr = (in_addr_t*)l3_addr.sa_data;
    
    IPv4Packet packet;
    packet.SetSourceAddress(ntohl(*ip_local));
    packet.SetDestinationAddress(ntohl(*ip_addr));
    packet.SetMoreFragments(true);
    packet.SetTTL(8);
    packet.SetProtocol(17); // UDP
    packet.SetData(l3_payload, 16);
    
    uint16_t len = 36;
    status = packet.Serialize(payload, len);
    
    status = eth.SendPacket(l3_addr, l3_addr, payload, len);
    
    std::cout << "Waiting for data" << std::endl;
    
    bool flag = false;
    do
    {
        _mutex.lock();
        flag = data_received;
        _mutex.unlock();
    } while (!flag);
    
    ASSERT_EQ(true, data_received);
    
    // Close the live capture
    eth.Close();
    eth1.Close();
    
    // Free device list
    pcap_freealldevs(alldevsp);
}
