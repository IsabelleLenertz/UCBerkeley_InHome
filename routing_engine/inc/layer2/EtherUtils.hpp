#ifndef INC_ETHERUTILS_HPP_
#define INC_ETHERUTILS_HPP_

#include <net/ethernet.h>

class EtherUtils
{
public:
    /// <summary>
    /// Parses an ethernet address from string
    /// Expects format: "aa:bb:cc:dd:ee:ff"
    /// </summary>
    /// <param name="str">Null-terminated string</param>
    /// <param name="addr">Ethernet Address Output</param>
    /// <returns>Error Code</returns>
    /// <remarks>
    /// If return value is non-zero, content of addr is undefined
    /// </remarks>
    static int AddressFromString(const char *str, struct ether_addr &addr);
    
    /// <summary>
    /// Given the name of an interface, gets
    /// the MAC address associated with that
    /// interface
    /// </summary>
    /// <param name="if_name">Interface name</param>
    /// <param name="addr">MAC address out</param>
    /// <returns>Error Code</returns>
    /// <remarks>
    /// If return value is non-zero, content of addr is undefined
    /// </remarks>
    static int GetMACAddress(const char *if_name, struct ether_addr &addr);
};

#endif
