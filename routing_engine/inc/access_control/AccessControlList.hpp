#ifndef INC_ACCESSCONTROLLIST_HPP_
#define INC_ACCESSCONTROLLIST_HPP_

#include "access_control/IAccessControlModule.hpp"

class AccessControlList : public IAccessControlModule
{
public:
	AccessControlList();
	~AccessControlList() override;

    bool IsAllowed(IIPPacket *packet);

    void SetConfiguration(IConfiguration* config);

    void SetARPTable(IARPTable *arp_table);

    void SetIPSecUtils(IIPSecUtils *ipsec);

private:
    IConfiguration *_config;
    IARPTable *_arp_table;
    IIPSecUtils *_ipsec_utils;
};

#endif
