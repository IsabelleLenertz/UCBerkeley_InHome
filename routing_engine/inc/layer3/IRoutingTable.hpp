#ifndef INC_IROUTINGTABLE_HPP_
#define INC_IROUTINGTABLE_HPP_

#include <netinet/in.h>
#include "layer2/ILayer2Interface.hpp"

/// <summary>
/// Generic interface defining functions for resolving
/// associations between IP addresses and Layer 2 interfaces,
/// independent of the underlying implementation. 
/// </summary>
class IRoutingTable
{
public:
    /// <summary>
    /// Given an IP address, returns a pointer to
    /// the Layer 2 interface with IP address matching
    /// the subnet
    /// </summary>
    /// <param name="ip_addr">Destination IP address</param>
    /// <returns>Pointer to Layer 2 interface</returns>
    /// <remarks>
    /// Returns nullptr if no interface exists on the same
    /// subnet as the specified address
    /// If multiple layer2 interfaces are mapped to the same
    /// subnet (which is not usually desirable), there is
    /// no guarantee which will be returned.
    /// </remarks>
    virtual ILayer2Interface *GetInterface(const struct sockaddr &ip_addr) = 0;
    
    /// <summary>
    /// Associates a Layer 2 interface with the specified
    /// subnet, as defined by an IP address and subnet mask
    /// </summary>
    /// <param name="interface">Layer 2 interface</param>
    /// <param name="ip_addr">Any IP address on the subnet</param>
    /// <param name="netmask">Subnet mask</param>
    virtual void AddSubnetAssociation(ILayer2Interface *interface, const struct sockaddr &ip_addr, const struct sockaddr &netmask) = 0;
    
    /// <summary>
    /// Locates and removes the subnet association for the specified
    /// subnet
    /// </summary>
    /// <param name="ip_addr">Any IP address on the subnet</param>
    /// <param name="netmask">Subnet mask</param>
    /// <remarks>
    /// If the specified association does not exist, this function
    /// has no effect.
    /// The subnet must be an exact match.
    /// </remarks>
    virtual void RemoveSubnetAssociation(const struct sockaddr &ip_addr, const struct sockaddr &netmask) = 0;
};

#endif
