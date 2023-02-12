#include "config/MySQLConfiguration.hpp"

MySQLConfiguration::MySQLConfiguration(uint16_t port)
    : _port(port)
{
}

MySQLConfiguration::~MySQLConfiguration()
{
}


bool MySQLConfiguration::LocalIsOutdated()
{
    // TODO Implement
    return false;
}

void MySQLConfiguration::UpdateLocal()
{
    // TODO Implement
}

bool MySQLConfiguration::GetDeviceKey(const struct ether_addr &mac_addr, DeviceKey_t &key)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::GetDeviceKey(const struct sockaddr &ip_addr, DeviceKey_t &key)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    // TODO Implement
    return true;
}
