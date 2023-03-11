#ifndef INC_INTERFACEMANAGER_HPP_
#define INC_INTERFACEMANAGER_HPP_

#include "layer2/EthernetInterface.hpp"
#include "layer2/WiFiInterface.hpp"
#include "layer3/IRoutingTable.hpp"
#include "layer3/IIPPacket.hpp"
#include "nat/NAPTTable.hpp"

#include <functional>

#define IM_IF_ETHERNET 0b0001
#define IM_IF_LOOPBACK 0b0010
#define IM_IF_WIRELESS 0b0100
#define IM_IF_INC_DOWN 0b1000

/// <summary>
/// A layer 3 receive callback is used to pass an
/// incoming IP packet up to layer 3
/// </summary>
typedef std::function<void(IIPPacket*)> Layer3ReceiveCallback;

/// <summary>
/// Aggregates available layer 2 interfaces
/// and provides abstraction for send
/// and receive actions
/// </summary>
class InterfaceManager
{
public:
    static const int SEND_BUFFER_SIZE = 4096;

    InterfaceManager(IARPTable *arp_table, IRoutingTable *ip_rte_table, NAPTTable *napt_table);
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
    int ListenAll(Layer3ReceiveCallback callback, NewARPEntryListener arp_listener);
    
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
    
    /// <summary>
    /// Callback to receive data from layer 2.
    /// </summary>
    /// <param name="_if">Pointer to interface on which data was received</param>
    /// <param name="data">Incoming data</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <remarks>
    /// Data received by this method must have an
    /// EtherType field of IPv4 or IPv6.
    /// </remarks>
    void ReceiveLayer2Data(ILayer2Interface *_if, const uint8_t *data, size_t len);

    /// <summary>
    /// Sets the default gateway IP address.
    /// IP addresses are stored for both IPv4
    /// and IPv6, differentiated by the address
    /// family of the input address.
    /// </summary>
    /// <param name="gateway_ip">IP address of the gateway</param>
    /// <param name="local_ip">Local address on same subnet</param>
    void SetDefaultGateway(const struct sockaddr &gateway_ip, const struct sockaddr &local_ip);

    /// <summary>
    /// Returns a pointer to the default gateway address
    /// for the specified IP version.
    /// </summary>
    /// <param name="version">IP version (4 or 6)</param>
    /// <returns>Pointer to IP address</returns>
    const struct sockaddr *GetDefaultGateway(int version);

private:
    std::vector<ILayer2Interface*> _interfaces;
    IARPTable *_arp_table;
    IRoutingTable *_ip_rte_table;
    NAPTTable *_napt_table;
    Layer3ReceiveCallback _callback;
    uint8_t _send_buff[SEND_BUFFER_SIZE];
    struct sockaddr_in _v4_gateway;
    struct sockaddr_in _v4_gateway_local;
    bool _v4_gateway_set;
    struct sockaddr_in6 _v6_gateway;
    struct sockaddr_in6 _v6_gateway_local;
    bool _v6_gateway_set;
    ILayer2Interface *_default_if;

    /// <summary>
    /// Associates an interface's addresses in the ARP
    /// and routing tables.
    /// </summary>
    /// <param name="_if">Interface object</param>
    /// <param name="pcap_if">PCAP interface</param>
    void _registerAddresses(ILayer2Interface* _if, pcap_if_t *pcap_if);
};

#endif
