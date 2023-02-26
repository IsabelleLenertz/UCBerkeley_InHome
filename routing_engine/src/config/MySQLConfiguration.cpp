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

bool MySQLConfiguration::GetDeviceSecurityParams(const struct sockaddr &ip_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::GetDeviceSecurityParams(const struct ether_addr &mac_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    // TODO Implement
    return true;
}
