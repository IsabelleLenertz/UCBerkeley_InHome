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
	// Internet-bound or -originating traffic does not require authentication headers
	if (packet->GetIsFromDefaultInterface() || packet->GetIsToDefaultInterface())
	{
		Logger::Log(LOG_DEBUG, "Authentication not required");
		return true;
	}

	Logger::Log(LOG_DEBUG, "Authenticating Message...");
	return (_ipsec_utils->ValidateAuthHeader(packet) == NO_ERROR);
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
