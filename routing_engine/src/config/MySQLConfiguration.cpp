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

bool MySQLConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    // TODO Implement
    return true;
}
