#include "access_control/CentralAccessControl.hpp"

CentralAccessControl::CentralAccessControl()
    : _modules(),
      _config(nullptr),
	  _arp_table(nullptr),
	  _ipsec_utils(nullptr)
{
}

CentralAccessControl::~CentralAccessControl()
{
}

bool CentralAccessControl::IsAllowed(IIPPacket *packet)
{
    bool result = true;
    
    // Iterate through submodules
    for (auto m = _modules.begin(); m < _modules.end(); m++)
    {
        // Check if this module allows the packet
        bool allowed = (*m)->IsAllowed(packet);
        
        // If this or any previous modules disallow
        // the packet, mark as not allowed
        result = result && allowed;
    }
    
    return result;
}

void CentralAccessControl::SetConfiguration(IConfiguration *config)
{
    _config = config;
}

void CentralAccessControl::SetARPTable(IARPTable *arp_table)
{
    _arp_table = arp_table;
}

void CentralAccessControl::AddModule(IAccessControlModule *module)
{
    _modules.push_back(module);
}

void CentralAccessControl::SetIPSecUtils(IIPSecUtils *ipsec)
{
	_ipsec_utils = ipsec;
}
