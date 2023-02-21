#ifndef INC_SYSYTEMARPTABLE_HPP_
#define INC_SYSYTEMARPTABLE_HPP_

#include "arp/IARPTable.hpp"

/// <summary>
/// Concrete implementation of IARPTable
/// which uses the system ARP table rather
/// than storing data in process memory
/// </summary>
class SystemARPTable : public IARPTable
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    SystemARPTable();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~SystemARPTable();
    
    void SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr);
    bool GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr);
};

#endif