#include "layer2/EtherUtils.hpp"
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <iostream>

int EtherUtils::AddressFromString(const char *str, struct ether_addr &addr)
{
    // Validate string length
    // Expected length is byte length of address
    // times 3 (2 digits, 1 delimiter), minus 1
    // since the last byte has no delimiter after
    static const int EXPECTED_LEN = ETH_ALEN * 3 - 1;
    
    if (strlen(str) != EXPECTED_LEN)
    {
        return 1;
    }
    
    // Check for invalid characters
    const char *c = str;
    while (*c != '\0')
    {
        // Digits 0-9
        // A-F, upper or lowercase
        // :, delimiter
        if (!((*c >= '0' && *c <= '9') ||
            (*c >= 'A' && *c <= 'F') ||
            (*c >= 'a' && *c <= 'f') ||
            *c == ':'))
        {
            // Invalid character detected
            return 2;
        }
        c++;
    }
    
    // Perform conversion
    c = str;
    char *end;
    int b_index = 0;
    
    while (*c != '\0')
    {
        if (*c == ':')
        {
            c++;
        }
    
        addr.ether_addr_octet[b_index++] = (char)strtol(c, &end, 16);
        c = end;
    }
    
    return 0;
}
