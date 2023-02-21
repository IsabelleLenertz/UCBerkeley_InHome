#include "arp/SystemARPTable.hpp"

#include <exception>

SystemARPTable::SystemARPTable()
{
}

SystemARPTable::~SystemARPTable()
{
}

void SystemARPTable::SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr)
{
}

bool SystemARPTable::GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr)
{
    return false;
}
