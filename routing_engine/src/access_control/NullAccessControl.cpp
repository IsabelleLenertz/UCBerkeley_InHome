#include "access_control/NullAccessControl.hpp"

NullAccessControl::NullAccessControl()
{
}

NullAccessControl::~NullAccessControl()
{
}

bool NullAccessControl::IsAllowed(const IIPPacket *packet)
{
    return true;
}

void NullAccessControl::SetConfiguration(IConfiguration* config)
{
}

void NullAccessControl::SetARPTable(IARPTable* arp_table)
{
}