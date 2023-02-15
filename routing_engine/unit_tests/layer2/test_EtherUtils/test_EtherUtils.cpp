#include "gtest/gtest.h"
#include "layer2/EtherUtils.hpp"
#include <cstring>

TEST(test_EtherUtils, test_lower)
{
    static const char str[] = "ab:cd:ef:12:34:56";
    static const uint8_t addr[ETH_ALEN] = {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56};
    
    struct ether_addr addr_out;
    
    int status = EtherUtils::AddressFromString(str, addr_out);
    ASSERT_EQ(0, status);
    
    ASSERT_EQ(0, memcmp(addr, addr_out.ether_addr_octet, ETH_ALEN));
}

TEST(test_EtherUtils, test_upper)
{
    static const char str[] = "AB:CD:EF:12:34:56";
    static const uint8_t addr[ETH_ALEN] = {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56};
    
    struct ether_addr addr_out;
    
    int status = EtherUtils::AddressFromString(str, addr_out);
    ASSERT_EQ(0, status);
    
    ASSERT_EQ(0, memcmp(addr, addr_out.ether_addr_octet, ETH_ALEN));
}

TEST(test_EtherUtils, test_too_short)
{
    static const char str[] = "AB:CD:EF";
    
    struct ether_addr addr_out;
    
    int status = EtherUtils::AddressFromString(str, addr_out);
    ASSERT_NE(0, status);
}

TEST(test_EtherUtils, test_too_long)
{
    static const char str[] = "AB:CD:EF:12:34:56:78:90";
    
    struct ether_addr addr_out;
    
    int status = EtherUtils::AddressFromString(str, addr_out);
    ASSERT_NE(0, status);
}

TEST(test_EtherUtils, test_invalid_char)
{
    static const char str[] = "AB:CD:EF;12:34:56";
    
    struct ether_addr addr_out;
    
    int status = EtherUtils::AddressFromString(str, addr_out);
    ASSERT_NE(0, status);
}
