#include "gtest/gtest.h"
#include "layer2/EthernetInterface.hpp"
#include "layer3/IPUtils.hpp"
#include "layer3/LocalRoutingTable.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

TEST(test_LocalRoutingTable, test_store_recall_v4)
{
    // Test-only. Does not refer to an actual interface
    EthernetInterface eth0("eth0", nullptr);
    EthernetInterface eth1("eth1", nullptr);
    
    LocalRoutingTable _table;
    
    // IP Address: 192.168.0.1
    struct sockaddr l3_addr_1;
    struct sockaddr_in &_l3_addr_1 = reinterpret_cast<struct sockaddr_in&>(l3_addr_1);
    _l3_addr_1.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.1", &_l3_addr_1.sin_addr);
    
    // IP Address: 192.168.0.2
    struct sockaddr l3_addr_2;
    struct sockaddr_in &_l3_addr_2 = reinterpret_cast<struct sockaddr_in&>(l3_addr_2);
    _l3_addr_2.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.2", &_l3_addr_2.sin_addr);
    
    // IP Address: 192.168.1.1
    struct sockaddr l3_addr_3;
    struct sockaddr_in &_l3_addr_3 = reinterpret_cast<struct sockaddr_in&>(l3_addr_3);
    _l3_addr_3.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.1", &_l3_addr_3.sin_addr);
    
    // Netmask: 255.255.255.0
    struct sockaddr netmask;
    struct sockaddr_in &_netmask = reinterpret_cast<struct sockaddr_in&>(netmask);
    _netmask.sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &_netmask.sin_addr);
    
    // Add subnet associations to routing table
    // Add incorrect choice first to ensure it isn't
    // just taking the first entry
    _table.AddSubnetAssociation(&eth1, l3_addr_3, netmask);
    _table.AddSubnetAssociation(&eth0, l3_addr_1, netmask);
    
    // Attempt to get the interface for another IP on the subnet
    ILayer2Interface *_if = _table.GetInterface(l3_addr_2);
    
    // Verify that the correct interface was returned
    ASSERT_EQ((ILayer2Interface*)&eth0, _if);
}
