#include "layer3/LocalRoutingTable.hpp"
#include <arpa/inet.h>
#include <cstring>

#include "layer3/IPUtils.hpp"

LocalRoutingTable::LocalRoutingTable()
    : _table()
{
}

LocalRoutingTable::~LocalRoutingTable()
{
}

ILayer2Interface* LocalRoutingTable::GetInterface(const struct sockaddr &ip_addr, const struct sockaddr **local_ip)
{
    // Iterate through entries
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.local_ip.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
            struct sockaddr entry_subnet, subnet;
            
            const struct sockaddr &entry_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            
            // Use entry subnet mask to calculate subnet ID
            // for the input IP address and the entry IP address
            IPUtils::GetSubnetID(ip_addr, entry_mask, subnet);
            IPUtils::GetSubnetID(entry_local_ip, entry_mask, entry_subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(subnet, entry_subnet))
            {
                *local_ip = reinterpret_cast<const struct sockaddr*>(&entry.local_ip);
                return entry.interface;
            }
        }
    }
    
    return nullptr;
}

void LocalRoutingTable::AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, const struct sockaddr &netmask)
{
    // Remove existing entry, if one exists
    RemoveSubnetAssociation(ip_addr, netmask);
    
    // Add an empty entry to the table
    _table.push_back({0});
    
    // Get a reference to the newly created
    // last entry in the table
    RoutingTableEntry_t &new_entry = _table.back();
    
    // Populate entry
    new_entry.interface = interface;
    IPUtils::StoreSockaddr(ip_addr, new_entry.local_ip);
    IPUtils::StoreSockaddr(netmask, new_entry.netmask);
}

void LocalRoutingTable::RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask)
{
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.local_ip.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
            struct sockaddr entry_subnet, subnet;
            
            const struct sockaddr &entry_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            
            // Use entry subnet mask to calculate subnet ID
            // for the input IP address and the entry IP address
            IPUtils::GetSubnetID(ip_addr, entry_mask, subnet);
            IPUtils::GetSubnetID(entry_local_ip, entry_mask, entry_subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(subnet, entry_subnet))
            {
                _table.erase(e);
                break;
            }
        }
    }
}
