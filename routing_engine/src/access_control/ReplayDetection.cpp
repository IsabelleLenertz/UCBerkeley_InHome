#include "access_control/ReplayDetection.hpp"
#include "status/error_codes.hpp"
#include "logging/Logger.hpp"

ReplayDetection::ReplayDetection()
	: _config(nullptr),
	  _arp_table(nullptr),
	  _ipsec_utils(nullptr)
{
}

ReplayDetection::~ReplayDetection()
{
}

bool ReplayDetection::IsAllowed(IIPPacket *packet)
{
	// Internet-bound or -originating traffic does not require authentication headers
	if (packet->GetIsFromDefaultInterface() || packet->GetIsToDefaultInterface())
	{
		return true;
	}

	Logger::Log(LOG_DEBUG, "Validating header sequence number...");
	return (_ipsec_utils->ValidateAuthHeaderSeqNum(packet) == NO_ERROR);
}

void ReplayDetection::SetConfiguration(IConfiguration* config)
{
	_config = config;
}

void ReplayDetection::SetARPTable(IARPTable* arp_table)
{
	_arp_table = arp_table;
}

void ReplayDetection::SetIPSecUtils(IIPSecUtils *ipsec)
{
	_ipsec_utils = ipsec;
}
