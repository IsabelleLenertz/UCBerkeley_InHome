#include "gtest/gtest.h"
#include "layer3/IPv4Packet.hpp"
#include <cstring>

/// <summary>
/// Given known IP packet data, deserializes
/// the data into an IPv4Packet object and
/// validates all getters
/// </summary>
TEST(test_IPv4Packet, test_deserialize)
{
    static const int HDR_LEN = 20;
    static const int TOTAL_LEN = 52;
    static const int TOS = 0;
    static const int STREAM_ID = 58112;
    static const int FRAGMENT_OFFSET = 0;
    static const int TTL = 55;
    static const int PROTOCOL = 6; // TCP
    
    // Addresses (in host byte order)
    static const uint8_t SRC_ADDR[4] = {0x31, 0xbe, 0x7d, 0xb9};
    static const uint8_t DEST_ADDR[4] = {0x2f, 0xe0, 0x10, 0xac};
    
    // Packet captured in Wireshark
    static const uint8_t pkt_data[TOTAL_LEN] =
        {0x45, 0x00, 0x00, 0x34, 0xe3, 0x00, 0x40, 0x00,
         0x37, 0x06, 0x5c, 0xd4, 0xb9, 0x7d, 0xbe, 0x31,
         0xac, 0x10, 0xe0, 0x2f, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
         0x00, 0x00, 0x00, 0x00};
    
    IPv4Packet pkt;
    int status = pkt.Deserialize(pkt_data, TOTAL_LEN);
    
    // Verify no error occurred
    ASSERT_EQ(0, status);
    
    // Verify header length (in bytes)
    ASSERT_EQ(HDR_LEN, pkt.GetHeaderLengthBytes());
    
    // Verify total packet length
    ASSERT_EQ(TOTAL_LEN, pkt.GetTotalLengthBytes());
    
    // Verify TOS is 0
    ASSERT_EQ(TOS, pkt.GetTOS());
    
    // Verify Stream ID
    ASSERT_EQ(STREAM_ID, pkt.GetStreamID());
    
    // Verify Don't Fragment
    ASSERT_EQ(true, pkt.GetDontFragment());
    
    // Verify More Fragments
    ASSERT_EQ(false, pkt.GetMoreFragments());
    
    // Verify Fragment Offset
    ASSERT_EQ(FRAGMENT_OFFSET, pkt.GetFragmentOffset());
    
    // Verify Time-to-Live (TTL)
    ASSERT_EQ(TTL, pkt.GetTTL());
    
    // Verify Protocol number
    ASSERT_EQ(PROTOCOL, pkt.GetProtocol());
    
    // Verify Source Address
    in_addr_t src_addr = pkt.GetSourceAddress();
    ASSERT_EQ(0, memcmp(SRC_ADDR, &src_addr, 4));
    
    // Verify Destination Address
    in_addr_t dest_addr = pkt.GetDestinationAddress();
    ASSERT_EQ(0, memcmp(DEST_ADDR, &dest_addr, 4));
    
    // Verify Data
    const uint8_t *data;
    uint16_t len = pkt.GetData(data);
    ASSERT_EQ(TOTAL_LEN - HDR_LEN, len);
    ASSERT_EQ(0, memcmp(pkt_data + HDR_LEN, data, len));
}

/// <summary>
/// Constructs an empty IPv4 packet object,
/// populates its values, serializes the packet,
/// deserializes, and checks values returned
/// by all getters
/// </summary>
TEST(test_IPv4Packet, test_serialize)
{
    static const int HDR_LEN = 20;
    static const int TOTAL_LEN = 52;
    static const int TOS = 0;
    static const int STREAM_ID = 58112;
    static const int FRAGMENT_OFFSET = 0;
    static const int TTL = 55;
    static const int PROTOCOL = 6; // TCP
    
    static const uint8_t SRC_ADDR[4] = {0x31, 0xbe, 0x7d, 0xb9};
    static const uint8_t DEST_ADDR[4] = {0x2f, 0xe0, 0x10, 0xac};
    
    static uint8_t DATA[TOTAL_LEN - HDR_LEN] = {0};
    
    IPv4Packet pkt;
    pkt.SetStreamID(STREAM_ID);
    pkt.SetDontFragment(true);
    pkt.SetFragmentOffset(FRAGMENT_OFFSET);
    pkt.SetTTL(TTL);
    pkt.SetProtocol(PROTOCOL);
    pkt.SetData(DATA, TOTAL_LEN - HDR_LEN);
    
    const in_addr_t *src_addrp = (in_addr_t*)SRC_ADDR;
    pkt.SetSourceAddress(*src_addrp);
    
    const in_addr_t *dest_addrp = (in_addr_t*)DEST_ADDR;
    pkt.SetDestinationAddress(*dest_addrp);
    
    // Serialize
    uint8_t pkt_data[TOTAL_LEN];
    uint16_t len = TOTAL_LEN;
    
    int status = pkt.Serialize(pkt_data, len);
    
    // Verify no error occurred
    ASSERT_EQ(0, status);
    
    // Verify length of output
    ASSERT_EQ(TOTAL_LEN, len);
    
    // Deserialize into new packet object
    IPv4Packet pkt2;
    status = pkt2.Deserialize(pkt_data, len);
    
    // Verify no error occurred
    ASSERT_EQ(0, status);
    
    // Verify header length (in bytes)
    ASSERT_EQ(HDR_LEN, pkt2.GetHeaderLengthBytes());
    
    // Verify total packet length
    ASSERT_EQ(TOTAL_LEN, pkt2.GetTotalLengthBytes());
    
    // Verify TOS is 0
    ASSERT_EQ(TOS, pkt2.GetTOS());
    
    // Verify Stream ID
    ASSERT_EQ(STREAM_ID, pkt2.GetStreamID());
    
    // Verify Don't Fragment
    ASSERT_EQ(true, pkt2.GetDontFragment());
    
    // Verify More Fragments
    ASSERT_EQ(false, pkt2.GetMoreFragments());
    
    // Verify Fragment Offset
    ASSERT_EQ(FRAGMENT_OFFSET, pkt2.GetFragmentOffset());
    
    // Verify Time-to-Live (TTL)
    ASSERT_EQ(TTL, pkt2.GetTTL());
    
    // Verify Protocol number
    ASSERT_EQ(PROTOCOL, pkt2.GetProtocol());
    
    // Verify Source Address
    in_addr_t src_addr = pkt2.GetSourceAddress();
    ASSERT_EQ(0, memcmp(SRC_ADDR, &src_addr, 4));
    
    // Verify Destination Address
    in_addr_t dest_addr = pkt2.GetDestinationAddress();
    ASSERT_EQ(0, memcmp(DEST_ADDR, &dest_addr, 4));
}
