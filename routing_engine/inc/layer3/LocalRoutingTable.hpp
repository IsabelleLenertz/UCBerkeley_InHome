#ifndef INC_LOCALROUTINGTABLE_HPP_
#define INC_LOCALROUTINGTABLE_HPP_

#include "layer3/IRoutingTable.hpp"

typedef struct
{
    ILayer2Interface *interface;
    uint8_t prefix_len;
    uint8_t subnet_id[4];
} RoutingTablev4Entry_t;

typedef struct
{
    ILayer2Interface *interface;
    uint8_t prefix_len;
    uint8_t subnet_id[16];
} RoutingTablev6Entry_t;

/// <summary>
/// Concrete implementation of IRoutingTable
/// using a table stored in local process memory
/// </summary>
class LocalRoutingTable : public IRoutingTable
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    LocalRoutingTable();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~LocalRoutingTable();
    
    ILayer2Interface *GetInterface(const struct sockaddr &ip_addr);
    void AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, uint8_t prefix_len);
    void RemoveSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, uint8_t prefix_len);

private:
    uint32_t _getIPv4SubnetID(uint32_t ip_addr, uint8_t prefix_len);

    std::vector<RoutingTablev4Entry_t> _v4table;
    std::vector<RoutingTablev6Entry_t> _v6table;
};

#endif