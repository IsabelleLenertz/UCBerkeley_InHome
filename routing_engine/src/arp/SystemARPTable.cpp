#include "arp/SystemARPTable.hpp"

#include <exception>

SystemARPTable::SystemARPTable()
{
    throw std::exception("SystemARPTable is not implemented!");
}

SystemARPTable::~SystemARPTable()
{
}

void SystemARPTable::SetARPEntry(const in_addr_t &l3_addr, const struct ether_addr &l2_addr)
{
}

bool SystemARPTable::(const in_addr_t &l3_addr, struct ether_addr& l2_addr)
{
    return false;
}