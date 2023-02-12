#ifndef INC_INTERFACEMANAGER_HPP_
#define INC_INTERFACEMANAGER_HPP_

#include "layer2/EthernetInterface.hpp"
#include "layer2/WiFiInterface.hpp"
#include "layer3/IRoutingTable.hpp"

#define IM_IF_ETHERNET 0b0001
#define IM_IF_LOOPBACK 0b0010
#define IM_IF_WIRELESS 0b0100
#define IM_IF_INC_DOWN 0b1000

/// <summary>
/// Aggregates available layer 2 interfaces
/// and provides abstraction for send
/// and receive actions
/// </summary>
class InterfaceManager
{
public:
    static const int SEND_BUFFER_SIZE = 4096;

    InterfaceManager(IARPTable *arp_table, IRoutingTable *ip_rte_table);
    ~InterfaceManager();
    
    /// <summary>
    /// Discovers available interfaces and
    /// populates the interface list with all
    /// interfaces matches the specified flags
    /// </summary>
    /// <param name="flags">
    /// Bitwise or of one or more:
    ///   IM_IF_ETHERNET: Include ethernet interfaces
    ///   IM_IF_LOOPBACK: Include loopback interfaces
    ///   IM_IF_WIRELESS: Include wireless interfaces
    ///   IM_IF_INC_DOWN: Include interfaces which are down
    /// </param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int InitializeInterfaces(int flags);
    
    /// <summary>
    /// Opens all known interfaces
    /// Calls ILayer2Interface:Open()
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int OpenAll();
    
    /// <summary>
    /// Closes all known interfaces
    /// Calls ILayer2Interface:Close()
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int CloseAll();
    
    /// <summary>
    /// Listens on all known interfaces
    /// </summary>
    /// <param name="callback">Receive Callback</param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int ListenAll(Layer2ReceiveCallback& callback);
    
    /// <summary>
    /// Stops listening on all known interfaces
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int StopListenAll();
    
    /// <summary>
    /// Send layer3 data
    /// </summary>
    int SendPacket(const uint8_t *data, size_t len);
    
private:
    std::vector<ILayer2Interface*> _interfaces;
    IARPTable *_arp_table;
    IRoutingTable *_ip_rte_table;
    uint8_t _send_buff[SEND_BUFFER_SIZE];
};

#endif
