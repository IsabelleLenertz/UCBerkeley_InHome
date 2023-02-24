#include "access_control/AccessControlList.hpp"

AccessControlList::AccessControlList()
    : _config(nullptr),
	  _arp_table(nullptr)
{
}

AccessControlList::~AccessControlList()
{
}

bool AccessControlList::IsAllowed(IIPPacket *packet)
{
	const struct sockaddr &src_addr = packet->GetSourceAddress();
	const struct sockaddr &dest_addr = packet->GetDestinationAddress();

	return _config->IsPermitted(src_addr, dest_addr);
}


void AccessControlList::SetConfiguration(IConfiguration* config)
{
	_config = config;
}

void AccessControlList::SetARPTable(IARPTable *arp_table)
{
	_arp_table = arp_table;
}
