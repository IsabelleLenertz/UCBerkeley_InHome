#include "access_control/NullAccessControl.hpp"

NullAccessControl::NullAccessControl()
{
}

NullAccessControl::~NullAccessControl()
{
}

bool NullAccessControl::IsAllowed(IIPPacket *packet)
{
    return true;
}

void NullAccessControl::SetConfiguration(IConfiguration* config)
{
}

void NullAccessControl::SetARPTable(IARPTable* arp_table)
{
}

void NullAccessControl::SetIPSecUtils(IIPSecUtils *ipsec)
{
}
