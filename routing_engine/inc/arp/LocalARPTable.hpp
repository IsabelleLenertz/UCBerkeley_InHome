#ifndef INC_LOCALARPTABLE_HPP_
#define INC_LOCALARPTABLE_HPP_

#include "arp/IARPTable.hpp"
#include <vector>

typedef struct
{
    in_addr_t l3_addr;
    struct ether_addr l2_addr;
} ARPEntry_t;

/// <summary>
/// Concrete implementation of IARPTable
/// which stores ARP table entries in local
/// process memory
/// <summary>
class LocalARPTable : public IARPTable
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    LocalARPTable();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~LocalARPTable();
    
    void SetARPEntry(const in_addr_t &l3_addr, const struct ether_addr &l2_addr);
    bool GetL2Address(const in_addr_t &l3_addr, struct ether_addr& l2_addr);

private:
    std::vector<ARPEntry_t> _table;
};

#endif
