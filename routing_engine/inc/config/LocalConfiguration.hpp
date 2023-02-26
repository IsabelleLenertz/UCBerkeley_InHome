#ifndef INC_LOCALCONFIGURATION_HPP_
#define INC_LOCALCONFIGURATION_HPP_

#include "config/IConfiguration.hpp"
#include <vector>

class LocalConfiguration : IConfiguration
{
public:
    LocalConfiguration();
    ~LocalConfiguration();
    
    bool LocalIsOutdated();
    void UpdateLocal();
    
    bool GetDeviceSecurityParams(const struct sockaddr &ip_addr, DeviceSecParams_t &params);
    bool GetDeviceSecurityParams(const struct ether_addr &mac_addr, DeviceSecParams_t &params);
    
    bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest);
    
    // Controls
    void SetDeviceSecurityParams(const struct sockaddr &ip_addr, const DeviceSecParams_t &params);
    void SetDeviceSecurityParams(const struct ether_addr &mac_addr, const DeviceSecParams_t &params);
    
    void SetAccessRule(const struct sockaddr &src, const struct sockaddr &src_mask, const struct sockaddr &dest, const struct sockaddr &dest_mask, bool allow);

private:
    std::vector<AccessRule_t> _rule_table;
};

#endif
