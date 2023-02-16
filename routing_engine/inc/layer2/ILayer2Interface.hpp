#ifndef INC_ILAYER2INTERFACE_HPP_
#define INC_ILAYER2INTERFACE_HPP_

#include <functional>
#include <sys/socket.h>
#include <cstdint>

/// <summary>
/// A Layer2ReceiveCallback is a callable object which defines a handler for
/// incoming packets on a Layer 2 Interface.
/// </summary>
/// <param>Pointer to incoming layer 3 data</param>
/// <param>Length of incoming layer 3 data, in bytes</param>
typedef std::function<void(const uint8_t *data, size_t len)> Layer2ReceiveCallback;

/// <summary>
/// Defines the base interface for all Layer 2 Interfaces.
/// Provides functionality to open a layer 2 interface,
/// initiate listening on that interface, and
/// send/receive layer3 packets
/// </summary>
class ILayer2Interface
{
public:
    /// <summary>
    /// Pure virtual destructor
    /// </summary>
    virtual ~ILayer2Interface() = default;

    /// <summary>
    /// Opens the layer 2 interface
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error, interface opened successfully
    ///   1: Error, interface not opened
    /// </returns>
    virtual int Open() = 0;
    
    /// <summary>
    /// Closes the layer 2 interface.
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error, interface closed successfully
    /// </returns>
    /// <remarks>
    /// If the interface is listening asynchronously, terminates the thread
    /// </remarks>
    virtual int Close() = 0;
    
    /// <summary>
    /// Begins listening for incoming packets on the device.
    /// Incoming packets are passed to callback.
    /// </summary>
    /// <param name="callback">Callback function. Must conform to Layer2ReceiveCallback</param>
    /// <param name="arp_listener">Callback for received ARP replies</param>
    /// <param name="async">If true, listens on a separate thread</param>
    /// <returns>
    /// Error Code:
    ///   0: No error, listening started successfully
    ///   1: Error, interface not opened
    /// </returns>
    /// <remarks>
    /// The following is an example of how to bind a callback:
    ///   void MyReceiveCallback(const uint8_t* data, uint8_t len);
    ///   Layer2ReceiveCallback _callback = std::bind(&MyReceiveCallback, std::placeholders::_1, std::placeholders::_2);
    ///   myLayer2Interface.SetReceiveCallback(_callback);
    /// </remarks>
    virtual int Listen(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener, bool async) = 0;
    
    /// <summary>
    /// Stops the listening thread
    /// </summary>
    /// <returns>
    /// Error Code:
    ///   0: No error, listening stopped successfully
    /// </returns>
    virtual int StopListen() = 0;

    /// <summary>
    /// Encapsulates a layer 3 packet in a layer 2 frame
    /// and sends the packet on the layer 2 interface
    /// </summary>
    /// <param name="l3_src_addr">Layer 3 Source Address</param>
    /// <param name="l3_dest_addr">Layer 3 Destination Address</param>
    /// <param name="data">Layer 3 Packet Data</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <returns>
    /// Error Code
    ///   0: No error, packet sent successfully
    ///   1: No error, packet queued for sending
    ///   2: Error, packet not sent
    /// </returns>
    /// <remarks>
    /// The Layer 3 source/destination address are used to resolve
    /// the Layer 2 source/destination addresses to be populated
    /// in the Layer 2 frame
    /// </remarks>
    virtual int SendPacket(const struct sockaddr &l3_src_addr, const struct sockaddr &l3_dest_addr, const uint8_t *data, size_t len) = 0;
    
    /// <summary>
    /// Gets the name of this interface
    /// </summary>
    /// <returns>Name string, null-terminated</returns>
    virtual const char *GetName() = 0;
    
    /// <summary>
    /// Sets the MAC address associated
    /// with this interface
    /// </summary>
    /// <param name="mac_addr">MAC Address</param>
    virtual void SetMACAddress(const struct ether_addr &mac_addr);
};

#endif
