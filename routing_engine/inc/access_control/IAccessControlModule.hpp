#ifndef INC_IACCESSCONTROLMODULE_HPP_
#define INC_IACCESSCONTROLMODULE_HPP_

#include <netinet/in.h>

#include "config/IConfiguration.hpp"
#include "layer3/IPPacket.hpp"

/// <summary>
/// Generic interface for access control modules.
/// Takes an IP packet and returns true if the
/// transaction is allowed by the module.
/// </summary>
/// <remarks>
/// All modules, including the central module,
/// MUST adhere to this interface
/// </remarks>
class IAccessControlModule
{
public:
    /// <summary>
    /// Given an IP packet, makes an authorization
    /// decision based on the module's configuration
    /// </summary>
    /// <param name="packet">IP Packet</param>
    /// <returns>True if packet is allowed<returns>
    /// <remarks>
    /// A return value of true does not guarantee
    /// that the packet will ultimately be allowed
    /// Only the central access control module may
    /// make the final authorization decision
    /// </remarks>
    virtual bool IsAllowed(const IPPacket &packet) = 0;
    
    /// <summary>
    /// Sets a pointer to the configuration module.
    /// Access control modules often need configuration
    /// information in order to make decisions.
    /// </summary>
    /// <param name="config">Pointer to config module</param>
    virtual void SetConfiguration(IConfiguration* config) = 0;
};

#endif