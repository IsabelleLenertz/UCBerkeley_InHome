#ifndef INC_INTERFACEMANAGER_HPP_
#define INC_INTERFACEMANAGER_HPP_

#include "layer2/EthernetInterface.hpp"
#include "layer2/WiFiInterface.hpp"
#include "layer3/IRoutingTable.hpp"
#include "layer3/IIPPacket.hpp"

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
    /// <param name="arp_listener">Callback for received ARP replies</param>
    /// <returns>
    /// Error Code:
    ///   0: No error
    /// </returns>
    int ListenAll(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener);
    
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
    /// <param name="packet">IP Packet to send</param>
    int SendPacket(IIPPacket *packet);
    
    /// <summary>
    /// Given the name of a layer 2 interface, returns
    /// a pointer to the interface object, or nullptr
    /// if no such interface exists.
    /// </summary>
    /// <param name="name">Interface name</param>
    ILayer2Interface* GetInterfaceFromName(const char *name);
    
private:
    std::vector<ILayer2Interface*> _interfaces;
    IARPTable *_arp_table;
    IRoutingTable *_ip_rte_table;
    Layer2ReceiveCallback _callback;
    uint8_t _send_buff[SEND_BUFFER_SIZE];
    
    /// <summary>
    /// Associates an interface's addresses in the ARP
    /// and routing tables.
    /// </summary>
    /// <param name="_if">Interface object</param>
    /// <param name="pcap_if">PCAP interface</param>
    void _registerAddresses(ILayer2Interface* _if, pcap_if_t *pcap_if);
};

#endif
