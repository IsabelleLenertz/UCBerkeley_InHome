#include "layer3/LocalRoutingTable.hpp"

LocalRoutingTable::LocalRoutingTable()
    : _table()
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
        
            for (auto e = _v4table.begin(); e < _4table.end(); e++)
            {
                uint32_t subnet_id = _getIPv4SubnetID(*(uint32_t*)ip_addr.sa_data, (*e).prefix_len);
                
                // If the subnet ID matches, this entry is a match
                if ((*e).subnet_id == subnet_id)
                {
                    return (*e).interface;
                }
            }
            
            break;
        }
        case AF_INET6:
        {
            throw std::exception("IPv6 routing support not implemented!");
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
            for (auto e = _v4table.begin(); e < _v4table.end(); e++)
            {
                uint32_t subnet_id = _getIPv4SubnetID(*(uint32_t*)ip_addr.sa_data, (*e).prefix_len);
                
                // Entry is a match only if subnet ID and netmask
                // are the same
                if ((*e).subnet_id == subnet_id &&
                    (*e).prefix_len == prefix_len)
                {
                    // If found, remove entry
                    _v4table.erase(e);
                    break;
                }
                
                RoutingTablev4Entry_t new_entry;
                new_entry.interface = interface;
                new_entry.prefix_len = prefix_len;
                new_entry.subnet_id = subnet_id;
                
                _v4table.push_back(new_entry);
            }
            
            break;
        }
        case AF_INET6:
        {
            throw std::exception("IPv6 routing support not implemented!");\
            break;
        }
        default:
        {
            break;
        }
    }
}

void LocalRoutingTable::RemoveSubnetAssociation(ILayer2Interface *interface, const in_addr_t &ip_addr, const in_addr_t subnet_mask)
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
                if ((*e).subnet_id == subnet_id &&
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
