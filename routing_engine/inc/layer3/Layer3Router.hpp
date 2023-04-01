#ifndef INC_LAYER3ROUTER_HPP_
#define INC_LAYER3ROUTER_HPP_

// #define DISABLE_AUTH

#include "access_control/AccessControlList.hpp"
#include "access_control/CentralAccessControl.hpp"
#include "access_control/NullAccessControl.hpp"
#include "access_control/MessageAuthentication.hpp"
#include "access_control/ReplayDetection.hpp"
#include "arp/LocalARPTable.hpp"
#include "concurrency/ConcurrentQueue.hpp"
#include "config/LocalConfiguration.hpp"
#include "config/MySQLConfiguration.hpp"
#include "interfaces/InterfaceManager.hpp"
#include "ipsec/LocalIPSecUtils.hpp"
#include "ipsec/NullIPSecUtils.hpp"
#include "layer2/ILayer2Interface.hpp"
#include "layer3/IIPPacket.hpp"
#include "layer3/LocalRoutingTable.hpp"
#include "nat/NAPTTable.hpp"

#define USE_LOCAL_CONFIG
#define USE_LOCAL_KEYS

#ifndef USE_LOCAL_KEYS
#include "keys/PFKeyManager.hpp"
#else
#include "keys/LocalKeyManager.hpp"
#endif

/// <summary>
/// Structure to store a message
/// which has been buffered due to
/// an ARP cache miss
/// </summary>
typedef struct
{
    IIPPacket *pkt;
    const struct sockaddr *next_hop;
    time_t expires_at;
} outstanding_msg_t;

/// <summary>
/// The Layer 3 Router is the top-level module
/// of the Routing Engine
/// <summary>
class Layer3Router
{
public:
    static const int SEND_BUFFER_SIZE = 4096;

    /// <summary>
    /// Default constructor
    /// </summary>
    Layer3Router();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~Layer3Router();
    
    /// <summary>
    /// Initializes the Layer 3 Router
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No Error
    ///   1: Failed to initialize layer 2 interfaces
    ///   2: Failed to open layer 2 interfaces for capture
    ///   3: Failed to listen on layer 2 interfaces
    /// </returns>
    int Initialize();
    
    /// <summary>
    /// Executes the main loop of the Layer 3 Router
    /// </summary>
    void MainLoop();

private:
    bool _exiting;

    // Interface Manager
    InterfaceManager _if_manager;
    time_t _next_monitor_time;

    // Configuration Module
#ifndef USE_LOCAL_CONFIG
    MySQLConfiguration _config;
#else
    LocalConfiguration _config;
#endif

    // ACE Modules
    CentralAccessControl _access_control;
    AccessControlList _access_list;
    NullAccessControl _null_access;
    MessageAuthentication _message_auth;
    ReplayDetection _replay_detect;
    
    // IPSec Utils
#ifndef DISABLE_AUTH
    LocalIPSecUtils _ipsec_utils;
#else
    NullIPSecUtils _ipsec_utils;
#endif

    // ARP Table
    LocalARPTable _arp_table;
    
    // Routing Table
    LocalRoutingTable _ip_rte_table;

    // NAPT Table
    NAPTTable _napt_table;

    // Key Management
#ifndef USE_LOCAL_KEYS
    PFKeyManager _key_manager;
#else
    LocalKeyManager _key_manager;
#endif

    /// <summary>
    /// Stores incoming layer 3 data
    /// </summary>
    /// <remarks>
    /// When dequeueing data, ownership of the data
    /// pointer transfers to the caller. The caller
    /// is responsible for freeing that memory.
    /// Failure to do so will result in a memory leak.
    /// </remarks>
    ConcurrentQueue<IIPPacket*> _rcv_queue;
    
    /// <summary>
    /// Stores packets which have been
    /// buffered due to ARP cache misses
    /// </summary>
    std::vector<outstanding_msg_t> _outstanding_msgs;
    
    /// <summary>
    /// Stores address information about
    /// incoming ARP replies
    /// </summary>
    ConcurrentQueue<struct sockaddr*> _arp_replies;
    
    /// <summary>
    /// Places incoming layer 3 packet data into
    /// the concurrent queue
    /// </summary>
    /// <param name="packet">Pointer to IP Packet</param>
    /// <remarks>
    /// Packet data must be dynamicall allocated.
    /// Layer3Router will free packet memory when
    /// no longer needed.
    /// </remarks>
    void _receive_packet(IIPPacket *packet);

    /// <summary>
    /// Processing an incoming layer 3 packet
    /// </summary>
    /// <param name="packet">Pointer to IP Packet</param>
    /// <remarks>
    /// The lifetime of the buffered packet data ends
    /// with this function. Memory must be freed before
    /// returning.
    /// </remarks>
    void _process_packet(IIPPacket *packet);
    
    /// <summary>
    /// Callback for incoming ARP replies
    /// Stores address information in
    /// the ARP reply queue
    /// </summary>
    void _queue_arp_reply(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr);
    
    /// <summary>
    /// Sends any outstanding messages relating
    /// to ARP replies in the ARP reply queue
    /// </summary>
    void _process_arp_replies();
    
    /// <summary>
    /// Removes any messages in the outstanding
    /// message buffer which have expired
    /// </summary>
    void _drop_stale_messages();
};

#endif
