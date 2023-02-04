#ifndef INC_LAYER3ROUTER_HPP_
#define INC_LAYER3ROUTER_HPP_

#include "access_control/CentralAccessControl.hpp"
#include "concurrency/ConcurrentQueue.hpp"
#include "config/IConfiguration.hpp"
#include "interfaces/InterfaceManager.hpp"
#include "layer2/ILayer2Interface.hpp"
#include "layer3/IPPacket.hpp"

/// <summary>
/// The Layer 3 Router is the top-level module
/// of the Routing Engine
/// <summary>
class Layer3Router
{
public:
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
    // Interface Manager
    InterfaceManager _if_manager;
    
    // Configuration Module
    Configuration _config;
    
    // ACE Modules
    CentralAccessControl _access_control;
    NullAccessControl _null_access;
    
    /// <summary>
    /// Stores incoming layer 3 data
    /// </summary>
    /// <remarks>
    /// When dequeueing data, ownership of the data
    /// pointer transfers to the caller. The caller
    /// is responsible for freeing that memory.
    /// Failure to do so will result in a memory leak.
    /// </remarks>
    ConcurrentQueue<std::pair<uint8_t*,size_t>> _rcv_queue;
    
    /// <summary>
    /// Places incoming layer 3 packet data into
    /// the concurrent queue
    /// </summary>
    /// <param name="data">Layer 3 Packet Data</param>
    /// <param name="len">Length of packet, in bytes</param>
    void _receive_packet(const uint8_t *data, size_t len
    
    /// <summary>
    /// Processing an incoming layer 3 packet
    /// </summary>
    /// <param name="data">Pointer to packet data</param>
    /// <param name="len">Length of packet, in bytes</param>
    /// <remarks>
    /// The lifetime of the buffered packet data ends
    /// with this function. Memory must be freed before
    /// returning.
    /// </remarks>
    void _process_packet(const uint8_t *data, size_t len);
}:

#endif