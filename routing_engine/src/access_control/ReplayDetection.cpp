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
	std::stringstream sstream;

	// Internet-bound or -originating traffic does not require authentication headers
	if (packet->GetIsFromDefaultInterface() || packet->GetIsToDefaultInterface())
	{
		return true;
	}

	int status = _ipsec_utils->ValidateAuthHeaderSeqNum(packet);

	switch (status)
	{
		case IPSEC_AH_ERROR_INVALID_SEQ_NUM:
		{
			sstream.str("");
			sstream << "Packet Denied (Replay Detected): " << Logger::IPToString(packet->GetSourceAddress()) <<
					" to " << Logger::IPToString(packet->GetDestinationAddress());
			Logger::Log(LOG_SECURE, sstream.str());
			break;
		}
		case NO_ERROR:
		{
			break;
		}
		default:
		{
			break;
		}
	}

	return (status == NO_ERROR);
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
