#include "gtest/gtest.h"
#include "layer3/IPUtils.hpp"
#include <arpa/inet.h>

#include <iostream>
#include <iomanip>

TEST(test_IPUtils, test_ipv4_addr_equal)
{
    struct sockaddr ip1, ip2;
    
    struct sockaddr_in &_ip1 = reinterpret_cast<struct sockaddr_in&>(ip1);
    struct sockaddr_in &_ip2 = reinterpret_cast<struct sockaddr_in&>(ip2);
    
    // Populate address structure 1
    _ip1.sin_family = AF_INET;
    _ip1.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.1", &_ip1.sin_addr);
    
    // Populate address structure 2
    _ip2.sin_family = AF_INET;
    _ip2.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.1", &_ip2.sin_addr);
    
    bool result = IPUtils::AddressesAreEqual(ip1, ip2);
    ASSERT_EQ(true, result);
}

TEST(test_IPUtils, test_ipv4_addr_not_equal)
{
    struct sockaddr ip1, ip2;
    
    struct sockaddr_in &_ip1 = reinterpret_cast<struct sockaddr_in&>(ip1);
    struct sockaddr_in &_ip2 = reinterpret_cast<struct sockaddr_in&>(ip2);
    
    // Populate address structure 1
    _ip1.sin_family = AF_INET;
    _ip1.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.1", &_ip1.sin_addr);
    
    // Populate address structure 2
    _ip2.sin_family = AF_INET;
    _ip2.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.2", &_ip2.sin_addr);
    
    bool result = IPUtils::AddressesAreEqual(ip1, ip2);
    ASSERT_EQ(false, result);
}

TEST(test_IPUtils, test_ipv6_addr_equal)
{
    struct sockaddr_storage ip1, ip2;
    
    struct sockaddr_in6 &_ip1 = reinterpret_cast<struct sockaddr_in6&>(ip1);
    struct sockaddr_in6 &_ip2 = reinterpret_cast<struct sockaddr_in6&>(ip2);
    
    // Populate address structure 1
    _ip1.sin6_family = AF_INET6;
    _ip1.sin6_port = 0;
    _ip1.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::1", &_ip1.sin6_addr);

    // Populate address structure 2
    _ip2.sin6_family = AF_INET6;
    _ip2.sin6_port = 0;
    _ip2.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::1", &_ip2.sin6_addr);
    
    struct sockaddr &__ip1 = reinterpret_cast<struct sockaddr&>(ip1);
    struct sockaddr &__ip2 = reinterpret_cast<struct sockaddr&>(ip2);
    
    bool result = IPUtils::AddressesAreEqual(__ip1, __ip2);
    ASSERT_EQ(true, result);
}


TEST(test_IPUtils, test_ipv6_addr_not_equal)
{
    struct sockaddr_storage ip1, ip2;
    
    struct sockaddr_in6 &_ip1 = reinterpret_cast<struct sockaddr_in6&>(ip1);
    struct sockaddr_in6 &_ip2 = reinterpret_cast<struct sockaddr_in6&>(ip2);
    
    // Populate address structure 1
    _ip1.sin6_family = AF_INET6;
    _ip1.sin6_port = 0;
    _ip1.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::1", &_ip1.sin6_addr);
    
    // Populate address structure 2
    _ip2.sin6_family = AF_INET6;
    _ip2.sin6_port = 0;
    _ip2.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::2", &_ip2.sin6_addr);
    
    struct sockaddr &__ip1 = reinterpret_cast<struct sockaddr&>(ip1);
    struct sockaddr &__ip2 = reinterpret_cast<struct sockaddr&>(ip2);
    
    bool result = IPUtils::AddressesAreEqual(__ip1, __ip2);
    ASSERT_EQ(false, result);
}

TEST(test_IPUtils, test_ipv4_subnet)
{
    struct sockaddr ip1, mask, subnet;
    
    struct sockaddr_in &_ip1 = reinterpret_cast<struct sockaddr_in&>(ip1);
    struct sockaddr_in &_mask = reinterpret_cast<struct sockaddr_in&>(mask);
    struct sockaddr_in &_subnet = reinterpret_cast<struct sockaddr_in&>(subnet);
    
    // Populate address structure
    _ip1.sin_family = AF_INET;
    _ip1.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.1", &_ip1.sin_addr);
    
    // Populate netmask structure
    _mask.sin_family = AF_INET;
    _mask.sin_port = 0;
    inet_pton(AF_INET, "255.255.255.0", &_mask.sin_addr);
    
    // Populate subnet structure
    _subnet.sin_family = AF_INET;
    _subnet.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.0", &_subnet.sin_addr);
    
    // Calculate subnet
    struct sockaddr subnet_out;
    IPUtils::GetSubnetID(ip1, mask, subnet_out);
    
    bool result = IPUtils::AddressesAreEqual(subnet, subnet_out);
    ASSERT_EQ(true, result);
}



TEST(test_IPUtils, test_ipv6_subnet)
{
    struct sockaddr_storage ip1, mask, subnet;
    
    struct sockaddr_in6 &_ip1 = reinterpret_cast<struct sockaddr_in6&>(ip1);
    struct sockaddr_in6 &_mask = reinterpret_cast<struct sockaddr_in6&>(mask);
    struct sockaddr_in6 &_subnet = reinterpret_cast<struct sockaddr_in6&>(subnet);
    
    // Populate address structure
    _ip1.sin6_family = AF_INET6;
    _ip1.sin6_port = 0;
    _ip1.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::1", &_ip1.sin6_addr);
    
    // Populate netmask structure
    _mask.sin6_family = AF_INET6;
    _mask.sin6_port = 0;
    _mask.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "ffff:ffff:ffff:ffff::", &_mask.sin6_addr);
    
    // Populate subnet structure
    _subnet.sin6_family = AF_INET6;
    _subnet.sin6_port = 0;
    _subnet.sin6_flowinfo = 0;
    inet_pton(AF_INET6, "fe80::", &_subnet.sin6_addr);
    
    struct sockaddr &__ip1 = reinterpret_cast<sockaddr&>(ip1);
    struct sockaddr &__mask = reinterpret_cast<sockaddr&>(mask);
    struct sockaddr &__subnet = reinterpret_cast<sockaddr&>(subnet);
    
    // Calculate subnet
    struct sockaddr_storage subnet_out;
    struct sockaddr &__subnet_out = reinterpret_cast<struct sockaddr&>(subnet_out);
    IPUtils::GetSubnetID(__ip1, __mask, __subnet_out);
    
    bool result = IPUtils::AddressesAreEqual(__subnet, __subnet_out);
    ASSERT_EQ(true, result);
}

TEST(test_IPUtils, test_ipv4_storage)
{
    struct sockaddr ip;
    struct sockaddr_storage ip_stored;
    
    struct sockaddr_in &_ip = reinterpret_cast<sockaddr_in&>(ip);
    _ip.sin_family = AF_INET;
    _ip.sin_port = 0;
    inet_pton(AF_INET, "192.168.0.1", &_ip.sin_addr);
    
    IPUtils::StoreSockaddr(ip, ip_stored);
    
    struct sockaddr &_ip_stored = reinterpret_cast<sockaddr&>(ip_stored);
    
    bool result = IPUtils::AddressesAreEqual(ip, _ip_stored);
    ASSERT_EQ(true, result);
}

TEST(test_IPUtils, test_ipv6_storage)
{
    struct sockaddr_storage ip;
    struct sockaddr_storage ip_stored;
    
    struct sockaddr_in6 &_ip = reinterpret_cast<sockaddr_in6&>(ip);
    _ip.sin6_family = AF_INET;
    _ip.sin6_port = 0;
    inet_pton(AF_INET6, "fe80::1", &_ip.sin6_addr);
    
    struct sockaddr &__ip = reinterpret_cast<sockaddr&>(ip);
    
    IPUtils::StoreSockaddr(__ip, ip_stored);
    
    struct sockaddr &_ip_stored = reinterpret_cast<sockaddr&>(ip_stored);
    
    bool result = IPUtils::AddressesAreEqual(__ip, _ip_stored);
    ASSERT_EQ(true, result);
}
