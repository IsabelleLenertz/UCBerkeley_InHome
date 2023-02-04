#include "layer2/WiFiInterface.hpp"

WiFiInterface::WiFiInterface(const char *if_name, IARPTable* arp_table)
    : _arp_table(arp_table)
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

int WiFiInterface::Listen(Layer2ReceiveCallback& callback, bool async)
{
    return 0;
}

int WiFiInterface::StopListen()
{
    return 0;
}

int WiFiInterface::SendPacket(const in_addr_t &l3_src_addr, const in_addr_t &l3_dest_addr, const uint8_t *data, size_t len)
{
    return 0;
}
