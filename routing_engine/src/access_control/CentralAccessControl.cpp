#include "access_control/CentralAccessModule.hpp"

CentralAccessControl::CentralAccessControl()
    : _modules(),
      _config(nullptr)
{
}

CentralAccessControl::~CentralAccessControl()
{
}

bool CentralAccessControl::IsAllowed(const IIPPacket *packet)
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

CentralAccessControl::SetConfiguration(IConfiguration* config)
{
    _config = config;
}

CentralAccessControl::AddModule(IAccessControlModule *module)
{
    _modules.push_back(module);
}