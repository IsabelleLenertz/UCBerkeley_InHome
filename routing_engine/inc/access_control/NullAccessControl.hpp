#ifndef INC_NULLACCESSCONTROL_HPP_
#define INC_NULLACCESSCONTROL_HPP_

#include "access_control/IAccessControlModule.hpp"

/// <summary>
/// The Null Access Control module is an access
/// control module which always returns true.
/// Essentially, it implements no access control.
/// <summary>
class NullAccessControl : public IAccessControlModule
{
public:
    NullAccessControl();
    ~NullAccessControl();
    
    bool IsAllowed(IIPPacket *packet);
    void SetConfiguration(IConfiguration* config);
    void SetARPTable(IARPTable *arp_table);
};

#endif
