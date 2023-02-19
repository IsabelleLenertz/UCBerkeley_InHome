#include "gtest/gtest.h"
#include "arp/ARPMessage.hpp"
#include <cstring>
#include <iomanip>
#include <iostream>

void print_eth_addr(uint8_t *data)
{
    std::cout << std::hex;
    
    for (int i = 0; i < 5; i++)
    {
        std::cout << +data[i] << ":";
    }
    std::cout << +data[5];
    
    std::cout << std::dec;
}

void dump_data(uint8_t *data, size_t len)
{
    std::cout << std::hex;
    for (size_t i = 0; i < len; i++)
    {
        std::cout << std::setw(2) << std::setfill('0') << +data[i];
        if ((i + 1) % 8 == 0)
        {
            std::cout << std::endl;
        }
        else
        {
            std::cout << " ";
        }
    }
    
    std::cout << std::dec;
    std::cout << std::endl;
}

/// <summary>
/// Test case for deserializing a message
/// from binary data, and accessing data
/// members.
/// </summary>
/// <remarks>
/// Binary data used in this test cases
/// is valid (message is not malformed).
/// Layer 3 addresses used are IPv4.
/// </remarks>
TEST(test_ARPMessage, test_Deserialize)
{
    static const uint8_t DATA_LEN = 28;
    static const uint8_t HW_ADDR_LEN = 6;
    static const uint8_t PROTO_ADDR_LEN = 4;

    uint8_t data[DATA_LEN]
    {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1,
     0xC0, 0xA8, 0x00, 0x01,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF2,
     0xC0, 0xA8, 0x00, 0x02};
    
    ARPMessage arp;
    int status = arp.Deserialize(data, DATA_LEN);
    ASSERT_EQ(status, 0);
    
    // Verify HW Type is Ethernet
    arp_hw_type_t hw_type = arp.GetHWType();
    ASSERT_EQ(hw_type, ARP_HW_TYPE_ETHERNET);
    
    // Verify Protocol type is IPv4
    arp_proto_type_t proto_type = arp.GetProtocolType();
    ASSERT_EQ(proto_type, ARP_PROTO_TYPE_IPV4);
    
    // Verify HW address length is 6 (48 bits)
    uint8_t hw_addr_len = arp.GetHWAddrLen();
    ASSERT_EQ(hw_addr_len, HW_ADDR_LEN);
    
    // Verify Protocol address length is 4 (32 bits)
    uint8_t proto_addr_len = arp.GetProtoAddrLen();
    ASSERT_EQ(proto_addr_len, PROTO_ADDR_LEN);
    
    // Verify Message type is ARP Reply
    arp_msg_type_t msg_type = arp.GetMessageType();
    ASSERT_EQ(msg_type, ARP_MSG_TYPE_REPLY);
    
    // Verify Sender HW Address
    uint8_t hw_addr_expected[HW_ADDR_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1};
    const uint8_t *hw_addr = arp.GetSenderHWAddress();
    ASSERT_EQ(0, memcmp(hw_addr_expected, hw_addr, HW_ADDR_LEN));
    
    // Verify Sender Protocol Address
    uint8_t proto_addr_expected[PROTO_ADDR_LEN] = {0xC0, 0xA8, 0x00, 0x01};
    const uint8_t *proto_addr = arp.GetSenderProtoAddress();
    ASSERT_EQ(0, memcmp(proto_addr_expected, proto_addr, PROTO_ADDR_LEN));
    
    // Verify Target HW Address
    hw_addr_expected[HW_ADDR_LEN - 1] = 0xF2;
    hw_addr = arp.GetTargetHWAddress();
    ASSERT_EQ(0, memcmp(hw_addr_expected, hw_addr, HW_ADDR_LEN));
    
    // Verify Target Protocol Address
    proto_addr_expected[PROTO_ADDR_LEN - 1] = 0x02;
    proto_addr = arp.GetTargetProtoAddress();
    ASSERT_EQ(0, memcmp(proto_addr_expected, proto_addr, PROTO_ADDR_LEN));
}

/// <summary>
/// Test case for serializing a message
/// to binary data.
/// </summary>
/// <remarks>
/// This test assumes that the Deserialize
/// test passes. If not, the result of this
/// test is indeterminate.
/// Layer 3 addresses used are IPv4.
/// </remarks>
TEST(test_ARPMessage, test_Serialize)
{
    static const uint8_t DATA_LEN = 28;
    static const uint8_t HW_ADDR_LEN = 6;
    static const uint8_t PROTO_ADDR_LEN = 4;

    uint8_t data[DATA_LEN]
    {0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1,
     0xC0, 0xA8, 0x00, 0x01,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF2,
     0xC0, 0xA8, 0x00, 0x02};
    
    ARPMessage arp;
    
    arp.SetHWType(ARP_HW_TYPE_ETHERNET);
    arp.SetProtocolType(ARP_PROTO_TYPE_IPV4);
    arp.SetMessageType(ARP_MSG_TYPE_REPLY);
    
    arp.SetHWAddrLen(HW_ADDR_LEN);
    arp.SetProtoAddrLen(PROTO_ADDR_LEN);
    
    uint8_t hw_addr_expected[HW_ADDR_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1};
    arp.SetSenderHWAddress(hw_addr_expected, HW_ADDR_LEN);
    hw_addr_expected[HW_ADDR_LEN - 1] = 0xF2;
    arp.SetTargetHWAddress(hw_addr_expected, HW_ADDR_LEN);
    
    uint8_t proto_addr_expected[PROTO_ADDR_LEN] = {0xC0, 0xA8, 0x00, 0x01};
    arp.SetSenderProtoAddress(proto_addr_expected, PROTO_ADDR_LEN);
    proto_addr_expected[PROTO_ADDR_LEN - 1] = 0x02;
    arp.SetTargetProtoAddress(proto_addr_expected, PROTO_ADDR_LEN);
    
    uint8_t data_out[DATA_LEN];
    size_t len = DATA_LEN;
    
    int status = arp.Serialize(data_out, len);
    ASSERT_EQ(status, 0);
    
    ASSERT_EQ(0, memcmp(data, data_out, DATA_LEN));
    
    ARPMessage arp2;
    status = arp2.Deserialize(data_out, len);
    
    // Verify HW Type is Ethernet
    arp_hw_type_t hw_type = arp2.GetHWType();
    ASSERT_EQ(hw_type, ARP_HW_TYPE_ETHERNET);
    
    // Verify Protocol type is IPv4
    arp_proto_type_t proto_type = arp2.GetProtocolType();
    ASSERT_EQ(proto_type, ARP_PROTO_TYPE_IPV4);
    
    // Verify HW address length is 6 (48 bits)
    uint8_t hw_addr_len = arp2.GetHWAddrLen();
    ASSERT_EQ(hw_addr_len, HW_ADDR_LEN);
    
    // Verify Protocol address length is 4 (32 bits)
    uint8_t proto_addr_len = arp2.GetProtoAddrLen();
    ASSERT_EQ(proto_addr_len, PROTO_ADDR_LEN);
    
    // Verify Message type is ARP Reply
    arp_msg_type_t msg_type = arp2.GetMessageType();
    ASSERT_EQ(msg_type, ARP_MSG_TYPE_REPLY);
    
    // Verify Sender HW Address
    hw_addr_expected[HW_ADDR_LEN - 1] = 0xF1;
    const uint8_t *hw_addr = arp2.GetSenderHWAddress();
    
    ASSERT_EQ(0, memcmp(hw_addr_expected, hw_addr, HW_ADDR_LEN));
    
    // Verify Sender Protocol Address
    proto_addr_expected[PROTO_ADDR_LEN - 1] = 0x01;
    const uint8_t *proto_addr = arp2.GetSenderProtoAddress();
    ASSERT_EQ(0, memcmp(proto_addr_expected, proto_addr, PROTO_ADDR_LEN));
    
    // Verify Target HW Address
    hw_addr_expected[HW_ADDR_LEN - 1] = 0xF2;
    hw_addr = arp2.GetTargetHWAddress();
    
    ASSERT_EQ(0, memcmp(hw_addr_expected, hw_addr, HW_ADDR_LEN));
    
    // Verify Target Protocol Address
    proto_addr_expected[PROTO_ADDR_LEN - 1] = 0x02;
    proto_addr = arp2.GetTargetProtoAddress();
    ASSERT_EQ(0, memcmp(proto_addr_expected, proto_addr, PROTO_ADDR_LEN));
}

/// <summary>
/// Test case for deserializing a message
/// from binary data, and accessing data
/// members.
/// </summary>
/// <remarks>
/// Binary data used in this test cases
/// is valid (message is not malformed).
/// Layer 3 addresses used are IPv6.
/// </remarks>
TEST(test_ARPMessage, test_DeserializeIPv6)
{

}

/// <summary>
/// Test case for serializing a message
/// to binary data.
/// </summary>
/// <remarks>
/// This test assumes that the Deserialize
/// test passes. If not, the result of this
/// test is indeterminate.
/// Layer 3 addresses used are IPv6.
/// </remarks>
TEST(test_ARPMessage, test_SerializeIPv6)
{

}

TEST(test_ARPMessage, test_Overflow)
{
    static const int DATA_LEN = 28;

    uint8_t data[DATA_LEN]
    {0x00, 0x01, 0x08, 0x00, 0x06, 0x10, 0x00, 0x02,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF1,
     0xC0, 0xA8, 0x00, 0x01,
     0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF2,
     0xC0, 0xA8, 0x00, 0x02};
     
    ARPMessage arp;
    int status = arp.Deserialize(data, DATA_LEN);
    
    ASSERT_NE(0, status);
}
