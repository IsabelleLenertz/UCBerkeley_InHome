#include "access_control/MessageAuthentication.hpp"
#include "logging/Logger.hpp"

MessageAuthentication::MessageAuthentication()
	: _config(nullptr),
	  _arp_table(nullptr),
	  _ipsec_utils(nullptr)
{
}

MessageAuthentication::~MessageAuthentication()
{
}

bool MessageAuthentication::IsAllowed(IIPPacket *packet)
{
	return _ipsec_utils->ValidateAuthHeader(packet);
}

void MessageAuthentication::SetConfiguration(IConfiguration* config)
{
	_config = config;
}

void MessageAuthentication::SetARPTable(IARPTable *arp_table)
{
	_arp_table = arp_table;
}

void MessageAuthentication::SetIPSecUtils(IIPSecUtils *ipsec)
{
	_ipsec_utils = ipsec;
}
