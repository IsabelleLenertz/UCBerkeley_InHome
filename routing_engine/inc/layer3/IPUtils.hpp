#ifndef INC_IPUTILS_HPP_
#define INC_IPUTILS_HPP_

#include <netinet/in.h>
#include <sys/socket.h>

/// <summary>
/// Provides utility functions for IP addresses
/// </summary>
class IPUtils
{
public:
    /// <summary>
    /// Given an IP address (v4 or v6) and a netmask,
    /// generates the subnet ID
    /// </summary>
    /// <param name="addr">IP address</param>
    /// <param name="netmask">Subnet mask</param>
    /// <param name="subnet_id">Subnet ID out</param>
    static void GetSubnetID(const struct sockaddr &addr, const struct sockaddr &netmask, struct sockaddr &subnet_id);
    
    /// <summary>
    /// Checks if the addresses represented by two sockaddr objects
    /// are equal. Only checks the IP address, not the port or
    /// other metadata.
    /// </summary>
    /// <param name="lhs">IP Address</param>
    /// <param name="rhs">IP Address</param>
    /// <returns>True if addresses are the same</returns>
    static bool AddressesAreEqual(const struct sockaddr &lhs, const struct sockaddr &rhs);
    
    /// <summary>
    /// Transfers an IP address (v4 or v6) to a storage structure
    /// </summary>
    /// <param name="src">Address to store</param>
    /// <param name="dst">Socket storage structure</param>
    static void StoreSockaddr(const struct sockaddr &src, struct sockaddr_storage &dst);

    /// <summary>
    /// Copies an IP address from one struct to another
    /// </summary>
    /// <param name="src">Address to store</param>
    /// <param name="dst">Destination address</param>
    /// <remarks>
    /// Destination MUST have sufficient room to store
    /// the source address type
    /// </remarks>
    static void CopySockaddr(const struct sockaddr &src, struct sockaddr &dst);

    /// <summary>
    /// Returns the actual size of the address stored,
    /// based on the address family
    /// </summary>
    /// <param name="addr">Socket address</param>
    /// <returns>Size of address, in bytes</returns>
    static size_t GetAddressSize(const struct sockaddr &addr);

    /// <summary>
    /// Calculates the 16-bit checksum of the specified data
    /// </summary>
    /// <param name="buff">Data to be checksummed</param>
    /// <param name="len">Length of data buffer, in bytes</param>
    /// <returns>16-bit checksum, in host byte order</returns>
    static uint16_t Calc16BitChecksum(const uint8_t *buff, size_t len);
};

#endif
