#include "layer2/EtherUtils.hpp"
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <fstream>

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


int EtherUtils::GetMACAddress(const char *if_name, struct ether_addr &addr)
{
    // Construct std::string to allow use of string concatenation
    std::string name(if_name);

    // Get MAC string from system files
    std::fstream file;
    std::string filename = "/sys/class/net/" + name + "/address";
    file.open(filename, std::ios::in);
    char mac_str[18];
    
    if (!file.is_open())
    {
        // Error opening file. Cannot continue
        return 1;
    }
    file.getline(mac_str, 18);
    
    // Convert MAC string to ether_addr
    struct ether_addr mac_addr;
    int status = EtherUtils::AddressFromString(mac_str, addr);
    
    return status;
}
