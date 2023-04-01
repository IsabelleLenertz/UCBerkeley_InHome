#ifndef INC_LOCALCONFIGURATION_HPP_
#define INC_LOCALCONFIGURATION_HPP_

#include "config/IConfiguration.hpp"
#include <vector>

typedef struct
{
	struct sockaddr_storage src_subnet_id;
	struct sockaddr_storage src_netmask;
	struct sockaddr_storage dest_subnet_id;
	struct sockaddr_storage dest_netmask;
	bool allowed;
} access_rule_t;

class LocalConfiguration : IConfiguration
{
public:
    LocalConfiguration();
    ~LocalConfiguration();
    
    bool LocalIsOutdated();
    void UpdateLocal();
    bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest);
    
    // Controls
    
    void SetAccessRule(const struct sockaddr &src, const struct sockaddr &src_mask, const struct sockaddr &dest, const struct sockaddr &dest_mask, bool allow);

private:
    std::vector<access_rule_t> _rule_table;

};

#endif
