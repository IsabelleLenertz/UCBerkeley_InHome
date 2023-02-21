#include "arp/LocalARPTable.hpp"
#include <exception>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <arpa/inet.h>

LocalARPTable::LocalARPTable()
    : _v4table(),
      _mutex()
{
}

LocalARPTable::~LocalARPTable()
{
}

void LocalARPTable::SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr)
{
    std::scoped_lock {_mutex};

    switch (l3_addr.sa_family)
    {
        case AF_INET:
        {
            // Get a pointer to the address segment of the
            // sockaddr structure. This is the IPv4 address
            uint32_t *addr1 = (uint32_t*)l3_addr.sa_data;
        
            // See if an entry exists for this L3 address
            // If so, remove it
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                if (*addr1 == *(uint32_t*)(*e).l3_addr)
                {
                    _v4table.erase(e);
                    break;
                }
            }
            
            // Add new entry
            ARPv4Entry_t new_entry;
            new_entry.l2_addr = l2_addr;
            memcpy(new_entry.l3_addr, addr1, sizeof(uint32_t));
            
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

bool LocalARPTable::GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr)
{
    std::scoped_lock {_mutex};

    bool found = false;
    
    switch (l3_addr.sa_family)
    {
        case AF_INET:
        {
            // Get a pointer to the address segment of the
            // sockaddr structure. This is the IPv4 address
            uint32_t *addr1 = (uint32_t*)l3_addr.sa_data;
            
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                // Check for matching layer 3 address
                if (*addr1 == *(uint32_t*)(*e).l3_addr)
                {
                    // Set output and break loop
                    l2_addr = (*e).l2_addr;
                    found = true;
                    break;
                }
            }
        
            break;
        }
        case AF_INET6:
        {
            break;
        }
    }
    
    return found;
}
