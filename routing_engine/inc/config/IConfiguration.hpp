#ifndef INC_ICONFIGURATION_HPP_
#define INC_ICONFIGURATION_HPP_

#include <sys/socket.h>
#include <net/ethernet.h>

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
    /// Returns true if access control rules permit sending a
    /// packet between source and destination IP addresses.
    /// </summary>
    /// <param name="src">Source IP Address</param>
    /// <param name="dest">Destination IP Address</param>
    /// <returns>True if transaction is permitted</returns>
    virtual bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest) = 0;
};

#endif
