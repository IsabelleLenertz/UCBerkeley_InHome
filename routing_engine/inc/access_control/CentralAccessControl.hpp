#ifndef INC_CENTRALACCESSCONTROL_HPP_
#define INC_CENTRALACCESSCONTROL_HPP_

#include <vector>

#include "access_control/IAccessControlModule.hpp"
#include "config/IConfiguration.hpp"

/// <summary>
/// The Central Access Control module aggregates
/// submodules and consults each of them to make
/// a final access control decision.
/// </summary>
class CentralAccessControl: public IAccessControlModule
{
public:
    CentralAccessControl();
    ~CentralAccessControl();
    
    bool IsAllowed(IIPPacket *packet);
    void SetConfiguration(IConfiguration* config);
    void SetARPTable(IARPTable *arp_table);
    
    /// <summary>
    /// Adds an access control module to the list
    /// of submodules consulted when making
    /// authorization decisions.
    /// </summary>
    /// <param name="module">Pointer to module to add</param>
    void AddModule(IAccessControlModule *module);
    
private:
    std::vector<IAccessControlModule*> _modules;
    IConfiguration *_config;
    IARPTable *_arp_table;
};

#endif
