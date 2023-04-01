#ifndef INC_MESSAGEAUTHENTICATION_HPP_
#define INC_MESSAGEAUTHENTICATION_HPP_

#include "access_control/IAccessControlModule.hpp"
#include "interfaces/InterfaceManager.hpp"

class MessageAuthentication : public IAccessControlModule
{
public:
	MessageAuthentication();
	~MessageAuthentication() override;

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
