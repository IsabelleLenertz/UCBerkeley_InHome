#include "layer3/LocalRoutingTable.hpp"
#include <arpa/inet.h>
#include <cstring>

#include <sstream>
#include "logging/Logger.hpp"

#include "layer3/IPUtils.hpp"

LocalRoutingTable::LocalRoutingTable()
    : _table(),
      _mutex()
{
}

LocalRoutingTable::~LocalRoutingTable()
{
}

ILayer2Interface* LocalRoutingTable::GetInterface(const struct sockaddr &ip_addr, struct sockaddr_storage &local_ip)
{
    std::scoped_lock {_mutex};
    
    // Iterate through entries
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the samelocal_ip
        if (entry.local_ip.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
            struct sockaddr_storage entry_subnet, subnet;
            struct sockaddr &_entry_subnet = reinterpret_cast<struct sockaddr&>(entry_subnet);
            struct sockaddr &_subnet = reinterpret_cast<struct sockaddr&>(subnet);
            
            const struct sockaddr &entry_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            
            // Use entry subnet mask to calculate subnet ID
            // for the input IP address and the entry IP address
            IPUtils::GetSubnetID(ip_addr, entry_mask, _subnet);
            IPUtils::GetSubnetID(entry_local_ip, entry_mask, _entry_subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(_subnet, _entry_subnet))
            {
            	switch (ip_addr.sa_family)
            	{
                    case AF_INET:
                    {
                        struct sockaddr_in &_local_ip = reinterpret_cast<struct sockaddr_in&>(local_ip);
                        const struct sockaddr_in &_entry_ip = reinterpret_cast<const struct sockaddr_in&>(entry_local_ip);

                        _local_ip.sin_family = AF_INET;
                        _local_ip.sin_port = _entry_ip.sin_port;
                        memcpy(&_local_ip.sin_addr, &_entry_ip.sin_addr, 4);

                        char ip_str[64];
                        inet_ntop(AF_INET, &_local_ip.sin_addr, ip_str, 64);
                        std::stringstream sstream;
                        sstream << "(LocalRoutingTable) Local IP: " << ip_str;
                        Logger::Log(LOG_DEBUG, sstream.str());

                    	break;
                    }
                    case AF_INET6:
                    {
                    	struct sockaddr_in6 &_local_ip = reinterpret_cast<struct sockaddr_in6&>(local_ip);
                    	const struct sockaddr_in6 &_entry_ip = reinterpret_cast<const struct sockaddr_in6&>(entry_local_ip);

                    	_local_ip.sin6_family = AF_INET6;
                    	_local_ip.sin6_port = _entry_ip.sin6_port;
                    	_local_ip.sin6_flowinfo = _entry_ip.sin6_flowinfo;
                    	memcpy(&_local_ip.sin6_addr, &_entry_ip.sin6_addr, 16);

                    	break;
                    }
                    default:
                    {
                    	return nullptr;
                    }
            	}

                return entry.interface;
            }
        }
    }
    
    return nullptr;
}

void LocalRoutingTable::AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, const struct sockaddr &netmask)
{
    // Only one entry may exist for a given subnet
    // at a time, so it is necessary to lock here
    std::scoped_lock {_mutex};

    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.local_ip.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
            struct sockaddr_storage entry_subnet, subnet;
            struct sockaddr &_entry_subnet = reinterpret_cast<struct sockaddr&>(entry_subnet);
            struct sockaddr &_subnet = reinterpret_cast<struct sockaddr&>(subnet);

            const struct sockaddr &entry_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            
            // Use entry subnet mask to calculate subnet ID
            // for the input IP address and the entry IP address
            IPUtils::GetSubnetID(ip_addr, entry_mask, _subnet);
            IPUtils::GetSubnetID(entry_local_ip, entry_mask, _entry_subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(_subnet, _entry_subnet))
            {
                _table.erase(e);
                break;
            }
        }
    }
    
    // Add an empty entry to the table
    _table.push_back({0});
    
    // Get a reference to the newly created
    // last entry in the table
    RoutingTableEntry_t &new_entry = _table.back();
    
    char ip_str[64];
    if (ip_addr.sa_family == AF_INET)
    {
    	const struct sockaddr_in &_ip_addr = reinterpret_cast<const struct sockaddr_in&>(ip_addr);
    	inet_ntop(AF_INET, &_ip_addr.sin_addr, ip_str, 64);
    	std::stringstream sstream;
    	sstream << "Adding local address: " << ip_str;
    	Logger::Log(LOG_DEBUG, sstream.str());
    }

    // Populate entry
    new_entry.interface = interface;
    IPUtils::StoreSockaddr(ip_addr, new_entry.local_ip);
    IPUtils::StoreSockaddr(netmask, new_entry.netmask);
}

void LocalRoutingTable::RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask)
{
    std::scoped_lock {_mutex};

    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        // Only evaluate if address family is the same
        if (entry.local_ip.ss_family == ip_addr.sa_family)
        {
            const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
            struct sockaddr_storage entry_subnet, subnet;
            struct sockaddr &_entry_subnet = reinterpret_cast<struct sockaddr&>(entry_subnet);
            struct sockaddr &_subnet = reinterpret_cast<struct sockaddr&>(subnet);
            
            const struct sockaddr &entry_mask = reinterpret_cast<const struct sockaddr&>(entry.netmask);
            
            // Use entry subnet mask to calculate subnet ID
            // for the input IP address and the entry IP address
            IPUtils::GetSubnetID(ip_addr, entry_mask, _subnet);
            IPUtils::GetSubnetID(entry_local_ip, entry_mask, _entry_subnet);
            
            // Compare Subnets. If they match,
            // then ip_addr is on that subnet
            if (IPUtils::AddressesAreEqual(_subnet, _entry_subnet))
            {
                _table.erase(e);
                break;
            }
        }
    }
}

bool LocalRoutingTable::IsOwnedByInterface(const ILayer2Interface *interface, const struct sockaddr &ip_addr)
{
	std::scoped_lock {_mutex};

    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        RoutingTableEntry_t& entry = *e;
        
        if (interface == entry.interface)
        {
            // Only compare if address families are the same
            if (entry.local_ip.ss_family == ip_addr.sa_family)
            {
                const struct sockaddr &entry_local_ip = reinterpret_cast<const struct sockaddr&>(entry.local_ip);
                
                if (IPUtils::AddressesAreEqual(ip_addr, entry_local_ip))
                {
                    return true;
                }
            }
        }
    }
    
    return false;
}
