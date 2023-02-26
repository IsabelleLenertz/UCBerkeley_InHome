#include "config/LocalConfiguration.hpp"
#include "layer3/IPUtils.hpp"
#include <cstring>
#include <arpa/inet.h>

#include "logging/Logger.hpp"
#include <sstream>

LocalConfiguration::LocalConfiguration()
    : _rule_table()
{
}

LocalConfiguration::~LocalConfiguration()
{
}

bool LocalConfiguration::LocalIsOutdated()
{
    return false;
}

void LocalConfiguration::UpdateLocal()
{
    // Master configuration is local
    // Nothing to be done for update
}

bool LocalConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    for (auto e = _rule_table.begin(); e < _rule_table.end(); e++)
    {
        AccessRule_t &entry = *e;

        // Only check if address families are the same
        if (entry.src_subnet_id.ss_family == src.sa_family)
        {
            // Get Source Subnet
            struct sockaddr_storage src_subnet;
            struct sockaddr &_src_subnet = reinterpret_cast<struct sockaddr&>(src_subnet);
            struct sockaddr &_src_netmask = reinterpret_cast<struct sockaddr&>(entry.src_netmask);
            struct sockaddr &_entry_src_subnet = reinterpret_cast<struct sockaddr&>(entry.src_subnet_id);
            IPUtils::GetSubnetID(src, _src_netmask, _src_subnet);

            // Skip entry if source subnet does not match
            if (!IPUtils::AddressesAreEqual(_src_subnet, _entry_src_subnet))
            {
                continue;
            }
            
            struct sockaddr_storage dest_subnet;
            struct sockaddr &_dest_subnet = reinterpret_cast<struct sockaddr&>(dest_subnet);
            struct sockaddr &_dest_netmask = reinterpret_cast<struct sockaddr&>(entry.dest_netmask);
            struct sockaddr &_entry_dest_subnet = reinterpret_cast<struct sockaddr&>(entry.dest_subnet_id);
            IPUtils::GetSubnetID(dest, _dest_netmask, _dest_subnet);
            
            // Skip entry if destination subnet does not match
            if (!IPUtils::AddressesAreEqual(_dest_subnet, _entry_dest_subnet))
            {
                continue;
            }

            // If this point is reached, source and destination match. Return result.
            return entry.allowed;
        }
    }
    
    return false;
}

bool LocalConfiguration::GetDeviceSecurityParams(const struct sockaddr &ip_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

bool LocalConfiguration::GetDeviceSecurityParams(const struct ether_addr &mac_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

void LocalConfiguration::SetDeviceSecurityParams(const struct sockaddr &ip_addr, const DeviceSecParams_t &params)
{
}

void LocalConfiguration::SetDeviceSecurityParams(const struct ether_addr &mac_addr, const DeviceSecParams_t &params)
{
}

void LocalConfiguration::SetAccessRule(const struct sockaddr &src, const struct sockaddr &src_mask, const struct sockaddr &dest, const struct sockaddr &dest_mask, bool allow)
{
    // Add a new entry and get a reference to that entry
    _rule_table.push_back(AccessRule_t { 0 });
    AccessRule_t &new_rule = _rule_table.back();

    // Get source subnet and store
    struct sockaddr &_src_subnet = reinterpret_cast<struct sockaddr&>(new_rule.src_subnet_id);
    IPUtils::GetSubnetID(src, src_mask, _src_subnet);

    // Store source mask
    IPUtils::StoreSockaddr(src_mask, new_rule.src_netmask);

    // Get destination subnet and store
    struct sockaddr &_dest_subnet = reinterpret_cast<struct sockaddr&>(new_rule.dest_subnet_id);
    IPUtils::GetSubnetID(dest, dest_mask, _dest_subnet);

    // Store destination mask
    IPUtils::StoreSockaddr(src_mask, new_rule.dest_netmask);

    new_rule.allowed = allow;
}
