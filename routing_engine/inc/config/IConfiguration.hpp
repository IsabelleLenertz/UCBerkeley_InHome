#ifndef INC_ICONFIGURATION_HPP_
#define INC_ICONFIGURATION_HPP_

#include <sys/socket.h>
#include <net/ethernet.h>

/// <summary>
/// Stores an Access Rule entry
/// </summary>
typedef struct
{
    struct sockaddr_storage src_subnet_id;
    struct sockaddr_storage src_netmask;
    struct sockaddr_storage dest_subnet_id;
    struct sockaddr_storage dest_netmask;
    bool allowed;
} AccessRule_t;

/// <summary>
/// Manages configuration information pulled
/// from the configuration database
/// </summary>
class IConfiguration
{
public:
    /// <summary>
    /// Returns true if a remote change was
    /// detected.
    /// </summary>
    /// <returns>True if local is out of sync with remote</returns>
    /// <remarks>
    /// The interface does not define how often the database
    /// must be checked, but the LocalIsOutdated() function MUST
    /// return true immediately upon becoming aware of a change.
    /// </remarks>
    virtual bool LocalIsOutdated() = 0;
    
    /// <summary>
    /// Initiate update of local database.
    /// If an update is already in progress,
    /// this function has no effect.
    /// </summary>
    /// <remarks>
    /// Upon completion, LocalIsOutdated will
    /// return false until an additional remote
    /// update is detected
    /// </remarks>
    virtual void UpdateLocal() = 0;
    
    /// <summary>
<<<<<<< routing_engine_sql_client
    /// Looks up the device security parameters
    /// associated with the specified IP address
    /// </summary>
    /// <param name="ip_addr">IP Address</param>
    /// <param name="params">Reference to security parameters output</param>
    /// <returns>True if entry was found</returns>
    /// <remarks>
    /// If return value is false, contents of params are undefined.
    /// This method may also be used to check if an entry exists for a specified
    /// device. There is a slight performance hit for copying the parameters, but
    /// not enough to be concerned with, as the copy only occurs when an entry is found.
    /// </remarks>
    virtual bool GetDeviceSecurityParams(const struct sockaddr &ip_addr, DeviceSecParams_t &params) = 0;
    
    /// <summary>
    /// Looks up the device security parameters
    /// associated with the specified MAC address
    /// </summary>
    /// <param name="mac_addr">Device MAC address</param>
    /// <param name="params">Reference to security parameters output</param>
    /// <returns>True if entry was found</returns>
    /// <remarks>
    /// If return value is false, contents of params are undefined.
    /// This method may also be used to check if an entry exists for a specified
    /// device. There is a slight performance hit for copying the parameters, but
    /// not enough to be concerned with, as the copy only occurs when an entry is found.
    /// </remarks>
    virtual bool GetDeviceSecurityParams(const struct ether_addr &mac_addr, DeviceSecParams_t &params) = 0;
    
    /// <summary>
=======
>>>>>>> main
    /// Returns true if access control rules permit sending a
    /// packet between source and destination IP addresses.
    /// </summary>
    /// <param name="src">Source IP Address</param>
    /// <param name="dest">Destination IP Address</param>
    /// <returns>True if transaction is permitted</returns>
    virtual bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest) = 0;
};

#endif
