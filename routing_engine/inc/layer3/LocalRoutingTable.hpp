#ifndef INC_LOCALROUTINGTABLE_HPP_
#define INC_LOCALROUTINGTABLE_HPP_

#include "layer3/IRoutingTable.hpp"

/// <summary>
/// Represents a single entry in the
/// routing table
/// </summary>
typedef struct
{
    in_addr_t subnet_id;
    in_addr_t netmask;
    ILayer2Interface *interface;
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
    
    ILayer2Interface *GetInterface(const in_addr_t &ip_addr);
    void AddSubnetAssociation(ILayer2Interface *interface, const in_addr_t &ip_addr, const in_addr_t subnet_mask);
    void RemoveSubnetAssociation(ILayer2Interface *interface, const in_addr_t &ip_addr, const in_addr_t subnet_mask);

private:
    std::vector<RoutingTableEntry_t> _table;
};

#endif