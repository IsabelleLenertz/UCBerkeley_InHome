#ifndef INC_LOCALCONFIGURATION_HPP_
#define INC_LOCALCONFIGURATION_HPP_

#include "config/IConfiguration.hpp"

typedef struct
{
    struct ether_addr l2_addr;
    uint8_t key[DEVICE_KEY_LEN];
} key_entry_t;

typedef struct
{
    struct sockaddr src_subnet_id;
    int src_prefix_len;
    struct sockaddr dest_subnet_id;
    int dest_prefix_len;
} access_rule_t;

class LocalConfiguration : IConfiguration
{
public:
    LocalConfiguration();
    ~LocalConfiguration();
    
    bool LocalIsOutdated();
    void UpdateLocal();
    bool GetDeviceKey(const struct ether_addr &mac_addr, DeviceKey_t &key);
    bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest);
    
    // Controls
    void SetDeviceKey(const struct ether_addr &mac_addr, const DeviceKey_t &key);
    
    void SetAccessRule(const struct sockaddr &src, int src_prefix_len, const struct sockaddr &dest, int dest_prefix_len, bool allow);

private:
    std::vector<key_entry_y> _key_table;
    
    uint32_t _getIPv4SubnetID(uint32_t ip_addr, uint8_t prefix_len);
};

#endif