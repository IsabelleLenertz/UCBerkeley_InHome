#include "arp/LocalARPTable.hpp"

LocalARPTable::LocalARPTable()
    : _table()
{
}

LocalARPTable::~LocalARPTable()
{
}

void LocalARPTable::SetARPEntry(const in_addr_t &l3_addr, const struct ether_addr &l2_addr)
{
    // See if an entry exists for this L3 address
    // If so, remove it
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        if ((*e).l3_addr == l3_addr)
        {
            _table.erase(e);
            break;
        }
    }
    
    // Add new entry
    _table.push_back(ARPEntry_t {l3_addr, l2_addr});
}

bool LocalARPTable::GetL2Address(const in_addr_t &l3_addr, struct ether_addr& l2_addr)
{
    bool found = false;
    
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
        // Check for matching layer 3 address
        if ((*e).l3_addr == l3_addr)
        {
            // Set output and break loop
            l2_addr = (*e).l2_addr;
            found = true;
            break;
        }
    }
    
    return found;
}
