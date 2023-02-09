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

void SetConfiguration(IConfiguration* config)
{
}