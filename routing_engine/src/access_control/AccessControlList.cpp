#include "access_control/AccessControlList.hpp"
#include "ipsec/IPSecAuthHeader.hpp"
#include "status/error_codes.hpp"
#include "layer3/IPPacketFactory.hpp"
#include "logging/Logger.hpp"

AccessControlList::AccessControlList()
    : _config(nullptr),
	  _arp_table(nullptr),
	  _ipsec_utils(nullptr)
{
}

AccessControlList::~AccessControlList()
{
}

bool AccessControlList::IsAllowed(IIPPacket *packet)
{
	std::stringstream sstream;

	if (packet->GetIsFromDefaultInterface() || packet->GetIsToDefaultInterface())
	{
		return true;
	}

	// Verify that this packet has an authentication header
	if (packet->GetProtocol() != IPPROTO_AH)
	{
		sstream.str("");
		sstream << "Packet Denied (Unauthorized Access): " << Logger::IPToString(packet->GetSourceAddress()) <<
				" to " << Logger::IPToString(packet->GetDestinationAddress());
		Logger::Log(LOG_SECURE, sstream.str());
		return false;
	}

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = packet->GetData(ip_payload);
	size_t auth_hdr_len_bytes = ip_payload_len_bytes;
	int status = auth_hdr.Deserialize(ip_payload, auth_hdr_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Update the source/destination address in the outer packet
	// Deserialize inner IP packet
	const uint8_t *auth_hdr_payload = (uint8_t*)(ip_payload + auth_hdr_len_bytes);
	size_t auth_hdr_payload_len_bytes = ip_payload_len_bytes - auth_hdr_len_bytes;
	IIPPacket *inner_pkt = IPPacketFactory::BuildPacket(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (inner_pkt == nullptr)
	{
		return IPV4_ERROR_INVALID_VERSION;
	}

	status = inner_pkt->Deserialize(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (status != NO_ERROR)
	{
		return status;
	}

	const struct sockaddr &src_addr = inner_pkt->GetSourceAddress();
	const struct sockaddr &dest_addr = inner_pkt->GetDestinationAddress();

	bool is_allowed = _config->IsPermitted(src_addr,  dest_addr);

	if (!is_allowed)
	{
		sstream.str("");
		sstream << "Packet Denied (Unauthorized Access): " << Logger::IPToString(packet->GetSourceAddress()) <<
				" to " << Logger::IPToString(packet->GetDestinationAddress());
		Logger::Log(LOG_SECURE, sstream.str());
	}

	return is_allowed;
}


void AccessControlList::SetConfiguration(IConfiguration* config)
{
	_config = config;
}

void AccessControlList::SetARPTable(IARPTable *arp_table)
{
	_arp_table = arp_table;
}

void AccessControlList::SetIPSecUtils(IIPSecUtils *ipsec)
{
	_ipsec_utils = ipsec;
}
