#include "gtest/gtest.h"
#include "layer3/LocalRoutingTable.hpp"
#include "layer2/EthernetInterface.hpp"

TEST(test_LocalRoutingTable, test_store_recall_v4)
{
    // Test-only. Does not refer to an actual interface
    EthernetInterface eth0("eth0", nullptr);
    EthernetInterface eth1("eth1", nullptr);
    
    LocalRoutingTable _table;
    
    // IP Address: 192.168.0.1
    static const uint8_t IP_1[4] = {0xC0, 0xA8, 0x00, 0x01};
    struct sockaddr l3_addr_1;
    l3_addr_1.sa_family = AF_INET;
    memcpy(l3_addr_1.sa_data, IP_1, 4);
    
    // IP Address: 192.168.0.2
    static const uint8_t IP_2[4] = {0xC0, 0xA8, 0x00, 0x02};
    struct sockaddr l3_addr_2;
    l3_addr_2.sa_family = AF_INET;
    memcpy(l3_addr_2.sa_data, IP_2, 4);
    
    // IP Address: 192.168.1.1
    static const uint8_t IP_3[4] = {0xC0, 0xA8, 0x01, 0x01};
    struct sockaddr l3_addr_3;
    l3_addr_3.sa_family = AF_INET;
    memcpy(l3_addr_3.sa_data, IP_3, 4);
    
    // Subnet Mask 255.255.255.0 (Prefix: /24)
    static const uint8_t PREFIX_LEN = 24;
    
    // Add subnet association to routing table
    _table.AddSubnetAssociation(&eth1, l3_addr_3, PREFIX_LEN);
    _table.AddSubnetAssociation(&eth0, l3_addr_1, PREFIX_LEN);
    
    // Attempt to get the interface for another IP on the subnet
    ILayer2Interface *_if = _table.GetInterface(l3_addr_2);
    
    // Verify that the correct interface was returned
    ASSERT_EQ(_if, (ILayer2Interface*)&eth0);
}
