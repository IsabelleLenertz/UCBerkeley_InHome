#include "layer3/LocalRoutingTable.hpp"

LocalRoutingTable::LocalRoutingTable()
    : _table()
{
}

LocalRoutingTable::~LocalRoutingTable()
{
}

ILayer2Interface* LocalRoutingTable::GetInterface(const in_addr_t &ip_addr)
{
    for (auto &e = _table.begin(); e < _table.end(); e++)
    {
        // If the subnet ID matches, this entry is a match
        if ((*e).subnet_id == (ip_addr & (*e)netmask))
        {
            return (*e)interface;
        }
    }
    
    return nullptr;
}

void LocalRoutingTable::AddSubnetAssociation(ILayer2Interface *interface, const in_addr_t &ip_addr, const in_addr_t subnet_mask)
{
    RoutingTableEntry_t *entry = nullptr;
    
    for (auto &e = _table.begin(); e < _table.end(); e++)
    {
        // Entry is a match only if subnet ID and netmask
        // are the same
        if ((*e).subnet_id == (ip_addr & subnet_mask) &&
            (*e).netmask == subnet_mask)
        {
            entry = &(*e);
            break;
        }
    }
    
    if (entry != nullptr)
    {
        // Entry found. Modify entry
        entry->interface = interface;
    }
    else
    {
        // Entry not found. Add new entry
        RoutingTableEntry_t new_entry
        {
            (ip_addr & subnet_mask),
            subnet_mask,
            interface
        }
        
        _table.push_back(new_entry);
    }
}

void LocalRoutingTable::RemoveSubnetAssociation(ILayer2Interface *interface, const in_addr_t &ip_addr, const in_addr_t subnet_mask)
{
    for (auto &e = _table.begin(); e < _table.end(); e++)
    {
        // Entry is a match only if subnet ID, netmask,
        // and interface are the same
        if ((*e).subnet_id == (ip_addr & subnet_mask) &&
            (*e).netmask == subnet_mask) &&
            (*e).interface == interface
        {
            _table.erase(e);
            break;
        }
    }
}