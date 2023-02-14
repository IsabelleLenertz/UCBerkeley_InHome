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

ILayer2Interface* LocalRoutingTable::GetInterface(const struct sockaddr &ip_addr)
{
    // Iterate through entries
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.subnet_id.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &if_subnet = reinterpret_cast<const struct sockaddr&>(entry.subnet_id);
            const struct sockaddr &if_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            struct sockaddr subnet;
            
            // Get subnet of input ip address using
            // netmask associated with the entry
            IPUtils::GetSubnetID(ip_addr, if_mask, subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(subnet, if_subnet))
            {
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
    
    // Get subnet from inputs
    struct sockaddr subnet;
    IPUtils::GetSubnetID(ip_addr, netmask, subnet);
    
    // Add an empty entry to the table
    _table.push_back({0});
    
    // Get a reference to the newly created
    // last entry in the table
    RoutingTableEntry_t &new_entry = _table.back();
    
    // Populate entry
    new_entry.interface = interface;
    IPUtils::StoreSockaddr(subnet, new_entry.subnet_id);
    IPUtils::StoreSockaddr(netmask, new_entry.netmask);
}

void LocalRoutingTable::RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask)
{
    struct sockaddr subnet;

    // Iterate through entries
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.subnet_id.ss_family == ip_addr.sa_family)
        {
            struct sockaddr& if_subnet = reinterpret_cast<struct sockaddr&>(entry.subnet_id);
            struct sockaddr& if_mask = reinterpret_cast<struct sockaddr&>(entry.netmask);
            
            IPUtils::GetSubnetID(ip_addr, if_mask, subnet);
            
            // TODO Compare Subnets
            bool match = false;
            if (match)
            {
                _table.erase(e);
                break;
            }
        }
    }
}
