#ifndef INC_IARPTABLE_HPP_
#define INC_IARPTABLE_HPP_

#include <netinet/in.h>
#include <net/ethernet.h>

/// <summary>
/// IARPTable provides a generic interface
/// for polling and modifying the ARP Table,
/// independent of the underlying implementation
/// </summary>
class IARPTable
{
public:
    /// <summary>
    /// Associates the specified L3 Address with
    /// the specified L2 address.
    /// </summary>
    /// <remarks>
    /// The association between L3 and L2 addresses is 1..* to 1
    /// That is, one L2 address may map to many L3 addresses, but
    /// an L3 address may only map to one L2 address.
    /// </remarks>
    virtual void SetARPEntry(const in_addr_t &l3_addr, const struct ether_addr &l2_addr) = 0;
    
    /// <summary>
    /// Given an L3 address, returns the corresponding L2 address.
    /// </summary>
    /// <param name="l3_addr">Layer 3 address</param>
    /// <param name="l2_addr">Reference to Layer 2 address output</param>
    /// <returns>True if L2 address was found</returns>
    /// <remarks>
    /// If the return value is false, the contents of l2_addr are undefined.
    /// </remarks>
    virtual bool GetL2Address(const in_addr_t &l3_addr, struct ether_addr& l2_addr) = 0;
};

#endif