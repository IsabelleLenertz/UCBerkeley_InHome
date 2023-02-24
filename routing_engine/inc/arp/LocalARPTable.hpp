#ifndef INC_LOCALARPTABLE_HPP_
#define INC_LOCALARPTABLE_HPP_

#include "arp/IARPTable.hpp"
#include <vector>
#include <cstdint>
#include <mutex>

/// <summary>
/// Stores a mapping between a layer 2 (MAC)
/// and layer 3 (IPv4/v6) address
/// </summary>
typedef struct
{
	struct ether_addr l2_addr;
	struct sockaddr_storage l3_addr;
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
    
    void SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr);
    bool GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr);

private:
    std::vector<ARPEntry_t> _table;
    
    std::mutex _mutex;
};

#endif
