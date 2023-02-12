#include "layer3/LocalRoutingTable.hpp"
#include <arpa/inet.h>
#include <cstring>

LocalRoutingTable::LocalRoutingTable()
    : _v4table(),
      _v6table()
{
}

LocalRoutingTable::~LocalRoutingTable()
{
}

ILayer2Interface* LocalRoutingTable::GetInterface(const struct sockaddr &ip_addr)
{
    switch (ip_addr.sa_family)
    {
        case AF_INET:
        {
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                uint32_t subnet_id = _getIPv4SubnetID(*(uint32_t*)ip_addr.sa_data, (*e).prefix_len);
                
                // If the subnet ID matches, this entry is a match
                if (*(uint32_t*)(*e).subnet_id == subnet_id)
                {
                    return (*e).interface;
                }
            }
            
            break;
        }
        case AF_INET6:
        {
            break;
        }
        default:
        {
            break;
        }
    }
    
    return nullptr;
}

void LocalRoutingTable::AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, uint8_t prefix_len)
{
    switch (ip_addr.sa_family)
    {
        case AF_INET:
        {
            uint32_t subnet_id = _getIPv4SubnetID(*(uint32_t*)ip_addr.sa_data, prefix_len);
            
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                // Entry is a match only if subnet ID and netmask
                // are the same
                if (*(uint32_t*)(*e).subnet_id == subnet_id &&
                    (*e).prefix_len == prefix_len)
                {
                    // If found, remove entry
                    _v4table.erase(e);
                    break;
                }
            }
            
            RoutingTablev4Entry_t new_entry;
            new_entry.interface = interface;
            new_entry.prefix_len = prefix_len;
            memcpy(new_entry.subnet_id, &subnet_id, 4);
              
            _v4table.push_back(new_entry);
            
            break;
        }
        case AF_INET6:
        {
            break;
        }
        default:
        {
            break;
        }
    }
}

void LocalRoutingTable::RemoveSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, uint8_t prefix_len)
{
    switch (ip_addr.sa_family)
    {
        case AF_INET:
        {
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                uint32_t subnet_id = _getIPv4SubnetID(*(uint32_t*)ip_addr.sa_data, (*e).prefix_len);
                
                // Entry is a match only if subnet ID, netmask,
                // and interface are the same
                if (*(uint32_t*)(*e).subnet_id == subnet_id &&
                    (*e).prefix_len == prefix_len &&
                    (*e).interface == interface)
                {
                    _v4table.erase(e);
                    break;
                }
            }
            
            break;
        }
        case AF_INET6:
        {
            break;
        }
        default:
        {
            break;
        }
    }
}

uint32_t LocalRoutingTable::_getIPv4SubnetID(uint32_t ip_addr, uint8_t prefix_len)
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
