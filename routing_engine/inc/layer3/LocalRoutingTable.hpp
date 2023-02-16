#ifndef INC_LOCALROUTINGTABLE_HPP_
#define INC_LOCALROUTINGTABLE_HPP_

#include "layer3/IRoutingTable.hpp"

typedef struct
{
    ILayer2Interface *interface;
    struct sockaddr_storage local_ip;
    struct sockaddr_storage netmask;
} RoutingTableEntry_t;

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
    
    ILayer2Interface *GetInterface(const struct sockaddr &ip_addr, const struct sockaddr *local_ip);
    void AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, const struct sockaddr &netmask);
    void RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask);

private:
    std::vector<RoutingTableEntry_t> _table;
};

#endif
