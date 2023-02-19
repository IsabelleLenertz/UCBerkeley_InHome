#ifndef INC_LOCALROUTINGTABLE_HPP_
#define INC_LOCALROUTINGTABLE_HPP_

#include "layer3/IRoutingTable.hpp"
#include <mutex>

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
    
    ILayer2Interface *GetInterface(const struct sockaddr &ip_addr, const struct sockaddr **local_ip);
    bool IsOwnedByInterface(const ILayer2Interface *interface, const struct sockaddr &ip_addr);
    void AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, const struct sockaddr &netmask);
    void RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask);

private:
    std::vector<RoutingTableEntry_t> _table;
    std::mutex _mutex;
};

#endif
