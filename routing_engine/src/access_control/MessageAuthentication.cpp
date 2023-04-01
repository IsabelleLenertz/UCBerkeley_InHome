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
	std::stringstream sstream;
	// Internet-bound or -originating traffic does not require authentication headers
	if (packet->GetIsFromDefaultInterface() || packet->GetIsToDefaultInterface())
	{
		return true;
	}

	int status = _ipsec_utils->ValidateAuthHeader(packet);

	switch (status)
	{
		case IPSEC_AH_ERROR_NO_AUTH_HEADER:
		{
			sstream.str("");
			sstream << "Packet Denied (No Authentication Header): " << Logger::IPToString(packet->GetSourceAddress()) <<
					" to " << Logger::IPToString(packet->GetDestinationAddress());
			Logger::Log(LOG_SECURE, sstream.str());
			break;
		}
		case IPSEC_AH_ERROR_INCORRECT_ICV:
		{
			sstream.str("");
			sstream << "Packet Denied (ICV Authentication Failure): " << Logger::IPToString(packet->GetSourceAddress()) <<
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
