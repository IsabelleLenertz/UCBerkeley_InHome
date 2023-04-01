#ifndef INC_REPLAYDETECTION_HPP_
#define INC_REPLAYDETECTION_HPP_

#include "access_control/IAccessControlModule.hpp"

class ReplayDetection : IAccessControlModule
{
public:
	ReplayDetection();
	~ReplayDetection();

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
