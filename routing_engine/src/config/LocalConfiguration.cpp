#include "config/LocalConfiguration.hpp"
#include <cstring>

LocalConfiguration();
~LocalConfiguration();

bool LocalConfiguration::LocalIsOutdated()
{
    return false;
}

void LocalConfiguration::UpdateLocal()
{
    // Master configuration is local
    // Nothing to be done for update
}

bool LocalConfiguration::GetDeviceKey(const struct ether_addr &mac_addr, DeviceKey_t &key)
{
    bool found = false;
    
    // Attempt to locate a key matching this MAC address
    for (auto e = _key_table.begin(); e < _key_table.end(); e++)
    {
        if (memcmp(&mac_addr, &(*e).l2_addr, ETH_ALEN) == 0)
        {
            // Copy key into output
            memcpy(key.key, (*e).key, DEVICE_KEY_LEN);
            found = true;
            break;
        }
    }
    
    return found;
}

bool LocalConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    // TODO Implement
    
    // Get Source subnet ID
    
    // Get Destination subnet ID
    
    // Locate Rule
    
    return false;
}

void LocalConfiguration::SetDeviceKey(const struct ether_addr &mac_addr, const DeviceKey_t &key)
{
    // Attempt to locate a key matching this MAC address
    for (auto e = _key_table.begin(); e < _key_table.end(); e++)
    {
        if (memcmp(&mac_addr, &(*e).l2_addr, ETH_ALEN) == 0)
        {
            // MAC Address match. Remove entry
            _key_table.erase(e);
            break;
        }
    }
    
    // Add new entry
    key_entry_t new_entry;
    memcpy(&new_entry.l2_addr, &mac_addr, ETH_ALEN);
    memcpy(new_entry.key, key.key, DEVICE_KEY_LEN);
    
    _key_table.push_back(new_entry);
}

void LocalConfiguration::SetAccessRule(const struct sockaddr &src, int src_prefix_len, const struct sockaddr &dest, int dest_prefix_len, bool allow)
{    
    // TODO Implement
}

uint32_t LocalConfiguration::_getIPv4SubnetID(uint32_t ip_addr, uint8_t prefix_len)
{
    // Space-efficient implementation
    uint32_t mask = 0;
    for (int i = 0; i < prefix_len; i++)
    {
        mask >>= 1;
        mask |= 0x80000000;
    }
    
    return ip_addr & ntohl(mask);
}
