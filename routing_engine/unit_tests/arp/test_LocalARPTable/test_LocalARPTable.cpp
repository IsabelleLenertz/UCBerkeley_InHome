#include "gtest/gtest.h"
#include "arp/LocalARPTable.hpp"
#include <cstring>

/// <summary>
/// Adds an IPv4 ARP table entry
/// and recalls it
/// </summary>
TEST(test_LocalARPTable, test_store_recall_v4)
{
   // IP Address: 192.168.0.1
   static const uint8_t IP[4] = {0xC0, 0xA8, 0x00, 0x01};
   struct sockaddr l3_addr;
   l3_addr.sa_family = AF_INET;
   memcpy(l3_addr.sa_data, IP, 4);
   
   
   struct ether_addr l2_addr {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
   
   // Construct the ARP Table object
   LocalARPTable _table;
   
   // Add an entry to the table
   _table.SetARPEntry(l3_addr, l2_addr);
   
   // Recall the entry
   struct ether_addr l2_addr_recall;
   bool found = _table.GetL2Address(l3_addr, l2_addr_recall);
   
   ASSERT_EQ(true, found);
   
   ASSERT_EQ(0, memcmp(&l2_addr, &l2_addr_recall, ETH_ALEN));
}

// At this time, IPv6 is not supported
/*
/// <summary>
/// Adds an IPv6 ARP table entry
/// and recalls it
/// </summary>
/// <remarks>
/// IPv6 actually uses Neighbor
/// Discover Protocol to replace
/// ARP functionality. The terms
/// are equated here for
/// interoperability.
/// </remarks>
TEST(test_LocalARPTable, test_store_recall_v6)
{
   // IP Address: 0xfe80::9607:ab2b:8feb:fa06
   uint8_t ip[16] = {0xfe, 0x80, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00,
                     0x96, 0x07, 0xab, 0x2b,
                     0x8f, 0xeb, 0xfa, 0x06};
   struct sockaddr l3_addr;
   l3_addr.sa_family = AF_INET6;
   memcpy(l3_addr.sa_data, ip, 16);
   
   struct ether_addr l2_addr {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
   
   // Construct the ARP Table object
   LocalARPTable _table;
   
   // Add an entry to the table
   _table.SetARPEntry(l3_addr, l2_addr);
   
   // Recall the entry
   struct ether_addr l2_addr_recall;
   bool found = _table.GetL2Address(l3_addr, l2_addr_recall);
   
   ASSERT_EQ(true, found);
   
   ASSERT_EQ(0, memcmp(&l2_addr, &l2_addr_recall, ETH_ALEN));
}
*/
