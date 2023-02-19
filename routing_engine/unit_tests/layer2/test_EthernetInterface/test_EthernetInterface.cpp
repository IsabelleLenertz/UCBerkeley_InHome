#include "gtest/gtest.h"
#include "arp/LocalARPTable.hpp"
#include "layer2/EthernetInterface.hpp"
#include "layer2/EtherUtils.hpp"
#include "layer3/IPv4Packet.hpp"
#include "layer3/LocalRoutingTable.hpp"
#include "pcap/pcap.h"
#include <iostream>
#include <functional>
#include <arpa/inet.h>

// Global receive flag
bool data_received = false;

std::mutex _mutex;

std::ostream& operator<<(std::ostream &lhs, const struct sockaddr &rhs)
{
    char addr_str[64];

    switch (rhs.sa_family)
    {
        case AF_INET:
        {
            lhs << std::dec;
            
            const struct sockaddr_in &_rhs = reinterpret_cast<const struct sockaddr_in&>(rhs);
            
            inet_ntop(AF_INET, &_rhs.sin_addr, addr_str, 64);
            lhs << addr_str;
            
            break;
        }
        default:
        {
            break;
        }
    }
    
    return lhs;
}

std::ostream& operator<<(std::ostream &lhs, const struct ether_addr &rhs)
{
    lhs << std::hex;
    
    for (int i = 0; i < ETH_ALEN; i++)
    {
        lhs << std::setw(2) << std::setfill('0') << +rhs.ether_addr_octet[i];
        if (i < ETH_ALEN - 1)
        {
            lhs << ":";
        }
    }
    lhs << std::dec;
    
    return lhs;
}

/// <summary>
/// Receive callback for ethernet frames.
/// </summary>
/// <param name="_if">Pointer to interface on which data was received</param>
/// <param name="data">Receive data</param>
/// <param name="len">Length of data, in bytes</param>
void receive_callback(ILayer2Interface *_if, const uint8_t *data, size_t len)
{
    IPv4Packet pkt;
    int status = pkt.Deserialize(data, len);
    
    if (status)
    {
        std::cout << "Error deserializing IP packet (" << status << ")" << std::endl;
        return;
    }
    
    char addr_str[32];
    
    const struct sockaddr_in& src_addr = reinterpret_cast<const struct sockaddr_in&>
        (pkt.GetSourceAddress());
    inet_ntop(AF_INET, &src_addr.sin_addr, addr_str, 32);
    
    std::cout << "Source Address: " << addr_str << std::endl;
    
    const struct sockaddr_in& dest_addr = reinterpret_cast<const struct sockaddr_in&>(pkt.GetDestinationAddress());
    inet_ntop(AF_INET, &dest_addr.sin_addr, addr_str, 32);
    
    std::scoped_lock lock {_mutex};
    data_received = true;
}

/// <summary>
/// ARP reply callback. Not used here
/// </summary>
void arp_listener(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr)
{    
    std::cout << "Added new ARP Entry for:" << std::endl;
    std::cout << "IP Address: " << l3_addr << std::endl;
    std::cout << "MAC Address: " << l2_addr << std::endl;
}

/*
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
    // TODO These IP addresses should be retrieved
    // using PCAP
    struct sockaddr l3_addr_local;
    struct sockaddr_in& _l3_addr_local = reinterpret_cast<sockaddr_in&>(l3_addr_local);
    _l3_addr_local.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.195", &_l3_addr_local.sin_addr);
    
    struct sockaddr l3_addr_remote;
    struct sockaddr_in& _l3_addr_remote = reinterpret_cast<sockaddr_in&>(l3_addr_remote);
    _l3_addr_remote.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.13", &_l3_addr_remote.sin_addr);
    
    struct ether_addr l2_addr_local
    {
        0x08, 0x00, 0x27, 0xd2, 0xb5, 0x87
    };
    struct ether_addr l2_addr_remote
    {
        0x08, 0x00, 0x27, 0x7d, 0xcb, 0xa8
    };
    
    LocalARPTable arp_table;
    arp_table.SetARPEntry(l3_addr_local, l2_addr_local); // Set ARP Entry for self
    arp_table.SetARPEntry(l3_addr_remote, l2_addr_remote);

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
    status = eth1.Listen(std::bind(receive_callback, std::placeholders::_1, std::placeholders::_2), std::bind(arp_listener, std::placeholders::_1, std::placeholders::_2), true);
    ASSERT_EQ(0, status);
    
    // Define an ethernet frame
    uint8_t payload[36];
    uint8_t l3_payload[16] = {0x80, 0x00, 0x80, 0x00, 0x08, 0x00, 0x00, 0x00,
                           'H', 'E', 'L', 'L', 'O', '!', 0x00, 0x00};
    
    IPv4Packet packet;
    packet.SetSourceAddress(l3_addr_local);
    packet.SetDestinationAddress(l3_addr_remote);
    packet.SetMoreFragments(true);
    packet.SetTTL(8);
    packet.SetProtocol(17); // UDP
    packet.SetData(l3_payload, 16);
    
    uint16_t len = 36;
    status = packet.Serialize(payload, len);
    
    status = eth.SendPacket(l3_addr_remote, l3_addr_remote, payload, len);
    
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
*/

TEST(test_EthernetInterface, test_arp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    int status;
    
    status = pcap_findalldevs(&alldevsp, errbuf);
    ASSERT_EQ(0, status);
    
    // Use first device
    pcap_if_t *dev = alldevsp;
    
    struct sockaddr *l3_addr_local = dev->addresses->next->addr;
    struct sockaddr_in &_l3_addr_local = reinterpret_cast<struct sockaddr_in&>(*l3_addr_local);
    
    struct sockaddr *l3_addr_remote = dev->next->addresses->next->addr;
    struct sockaddr_in &_l3_addr_remote = reinterpret_cast<struct sockaddr_in&>(*l3_addr_local);
    
    struct ether_addr l2_addr_local;
    struct ether_addr l2_addr_remote;
    
    status = EtherUtils::GetMACAddress(dev->name, l2_addr_local);
    status = EtherUtils::GetMACAddress(dev->next->name, l2_addr_remote);
    
    ASSERT_EQ(0, status);
    
    LocalARPTable arp_table;
    LocalRoutingTable ip_rte_table;
    
    // Build an ethernet interface around
    // the first device
    EthernetInterface eth(dev->name, &arp_table);
    EthernetInterface eth1(dev->next->name, &arp_table);
    
    struct sockaddr mask;
    struct sockaddr_in &_mask = reinterpret_cast<sockaddr_in&>(mask);
    _mask.sin_family = AF_INET;
    _mask.sin_port = 0;
    inet_pton(AF_INET, "255.255.255.0", &_mask.sin_addr);
    ip_rte_table.AddSubnetAssociation(&eth, *l3_addr_local, mask);
    ip_rte_table.AddSubnetAssociation(&eth1, *l3_addr_remote, mask);
    eth.SetIPAddressQueryMethod(std::bind(&IRoutingTable::IsOwnedByInterface, &ip_rte_table, std::placeholders::_1, std::placeholders::_2)); eth1.SetIPAddressQueryMethod(std::bind(&IRoutingTable::IsOwnedByInterface, &ip_rte_table, std::placeholders::_1, std::placeholders::_2));
    
    eth.SetMACAddress(l2_addr_local);
    eth1.SetMACAddress(l2_addr_remote);
    
    // Open ethernet interface for live capture
    eth.Open();
    eth1.Open();
    
    // Listen on ethernet interface
    status = eth.Listen(std::bind(receive_callback, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), std::bind(arp_listener, std::placeholders::_1, std::placeholders::_2), true);
    ASSERT_EQ(0, status);
    
    status = eth1.Listen(std::bind(receive_callback, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), std::bind(arp_listener, std::placeholders::_1, std::placeholders::_2), true);
    ASSERT_EQ(0, status);
    
    // Define an ethernet frame
    uint8_t payload[36];
    uint8_t l3_payload[16] = {0x80, 0x00, 0x80, 0x00, 0x08, 0x00, 0x00, 0x00,
                           'H', 'E', 'L', 'L', 'O', '!', 0x00, 0x00};
    
    IPv4Packet packet;
    packet.SetSourceAddress(*l3_addr_local);
    packet.SetDestinationAddress(*l3_addr_remote);
    packet.SetMoreFragments(true);
    packet.SetTTL(8);
    packet.SetProtocol(17); // UDP
    packet.SetData(l3_payload, 16);
    
    uint16_t len = 36;
    status = packet.Serialize(payload, len);
    
    status = eth.SendPacket(*l3_addr_local, *l3_addr_remote, payload, len);
    
    // Halt for 1 second
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Attempt to retrieve MAC address from ARP table
    bool hit = arp_table.GetL2Address(*l3_addr_remote, l2_addr_remote);
    
    ASSERT_EQ(true, hit);
    
    // Close the live capture
    eth.Close();
    eth1.Close();
    
    // Free device list
    pcap_freealldevs(alldevsp);
}
