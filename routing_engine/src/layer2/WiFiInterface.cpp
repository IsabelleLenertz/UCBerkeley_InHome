#include "layer2/WiFiInterface.hpp"

WiFiInterface::WiFiInterface(const char *if_name, IARPTable* arp_table)
    : _arp_table(arp_table),
	  _is_default(false)
{
    _if_name = std::string(if_name);
}

WiFiInterface::~WiFiInterface()
{
}

int WiFiInterface::Open()
{
    return 0;
}

int WiFiInterface::Close()
{
    return 0;
}

int WiFiInterface::Listen(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener, bool async)
{
    return 0;
}

int WiFiInterface::StopListen()
{
    return 0;
}

int WiFiInterface::SendPacket(const struct sockaddr &l3_src_addr, const struct sockaddr &l3_dest_addr, const uint8_t *data, size_t len)
{
    return 0;
}

const char *WiFiInterface::GetName()
{
    return _if_name.c_str();
}

void WiFiInterface::SetMACAddress(const struct ether_addr& mac_addr)
{
}

void WiFiInterface::SetIPAddressQueryMethod(IPOwnershipQuery method)
{
}

void WiFiInterface::SetAsDefault()
{
	_is_default = true;
}
