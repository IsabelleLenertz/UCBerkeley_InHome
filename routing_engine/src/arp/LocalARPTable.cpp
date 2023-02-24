#include "arp/LocalARPTable.hpp"
#include "layer3/IPUtils.hpp"

#include <exception>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <arpa/inet.h>

LocalARPTable::LocalARPTable()
    : _table(),
      _mutex()
{
}

LocalARPTable::~LocalARPTable()
{
}

void LocalARPTable::SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr)
{
    std::scoped_lock {_mutex};

    for (auto e = _table.begin(); e < _table.end(); e++)
    {
    	const ARPEntry_t& entry = *e;
    	const struct sockaddr &_entry_l3_addr = reinterpret_cast<const struct sockaddr&>(entry.l3_addr);

    	if (IPUtils::AddressesAreEqual(l3_addr, _entry_l3_addr))
    	{
    		_table.erase(e);
    		break;
    	}
    }

    // Create empty entry
    _table.push_back(ARPEntry_t { 0 });

    // Get reference to new entry
    ARPEntry_t &new_entry = _table.back();

    // Populate new entry
    memcpy(&new_entry.l2_addr, &l2_addr, ETH_ALEN);
    IPUtils::StoreSockaddr(l3_addr, new_entry.l3_addr);
}

bool LocalARPTable::GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr)
{
    std::scoped_lock {_mutex};

    bool found = false;
    
    for (auto e = _table.begin(); e < _table.end(); e++)
    {
    	const ARPEntry_t &entry = *e;
    	const struct sockaddr &_entry_l3_addr = reinterpret_cast<const struct sockaddr&>(entry.l3_addr);

    	if (IPUtils::AddressesAreEqual(l3_addr, _entry_l3_addr))
    	{
    		memcpy(&l2_addr, &entry.l2_addr, ETH_ALEN);
    		found = true;
    		break;
    	}
    }
    
    return found;
}
