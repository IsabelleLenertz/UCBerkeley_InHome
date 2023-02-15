#include "layer3/Layer3Router.hpp"

#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <thread>
#include <arpa/inet.h>

#include "layer3/IPPacketFactory.hpp"

Layer3Router::Layer3Router()
    : _if_manager(&_arp_table, &_ip_rte_table),
      _config((uint16_t)3306),
      _access_control(),
      _rcv_queue(),
      _exiting(false)
{
}

Layer3Router::~Layer3Router()
{
}

int Layer3Router::Initialize()
{
    int status;

    ////////////////////////////////////
    //////// Layer 2 Interfaces ////////
    ////////////////////////////////////

    // Initialize Ethernet Interfaces Only
    status = _if_manager.InitializeInterfaces(IM_IF_ETHERNET);

    if (status != 0)
    {
        std::cout << "Failed to initialize interfaces" << std::endl;
        return 1;
    }

    // Open all interfaces
    status = _if_manager.OpenAll();
    
    if (status != 0)
    {
        std::cout << "Failed to open interfaces" << std::endl;
        return 2;
    }

    // Bind receive callback
    Layer2ReceiveCallback callback = std::bind(&Layer3Router::_receive_packet, this, std::placeholders::_1, std::placeholders::_2);
    
    // Listen asynchronously on all interfaces
    status = _if_manager.ListenAll(callback);
    
    if (status != 0)
    {
        std::cout << "Failed to listen on interfaces" << std::endl;
        return 3;
    }

    ////////////////////////////////
    /////// Static ARP Setup ///////
    ////////////////////////////////

    ////////////////////////////////
    // Static Routing Table Setup //
    ////////////////////////////////

    ////////////////////////////////
    //////// Access Control ////////
    ////////////////////////////////

    // Associate configuration module
    // with each access control module
    _access_control.SetConfiguration((IConfiguration*)&_config);
    _null_access.SetConfiguration((IConfiguration*)&_config);

    // Add submodules to central module
    _access_control.AddModule((IAccessControlModule*)&_null_access);

    return 0;
}

void Layer3Router::MainLoop()
{
    while (!_exiting)
    {
        // Check for changes in configuration
        while (_config.LocalIsOutdated())
        {
            // Command Update
            _config.UpdateLocal();

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Check for data in receive queue
        if (!_rcv_queue.IsEmpty())
        {
            // Get data from queue
            queued_message_t msg;
            _rcv_queue.Dequeue(msg);
            
            // Pass to packet processing
            _process_packet(msg.data, msg.len);
        }
    }
}

void Layer3Router::_receive_packet(const uint8_t *data, size_t len)
{
    std::cout << "Copying " << len << " bytes into buffer" << std::endl;

    // Copy into storage buffer
    uint8_t *buff = new uint8_t[len];
    memcpy(buff, data, len);
    
    // Add to receive queue
    // Ownership of buff pointer transfers
    // to receive queue
    _rcv_queue.Enqueue(queued_message_t {len, buff});
}

void Layer3Router::_process_packet(const uint8_t *data, size_t len)
{
    std::cout << std::dec;
    std::cout << len << " bytes received at Layer 3" << std::endl;
    
    // TODO Need to switch to abstract factory pattern
    // Temporary: Assume IPv4 packet
    IIPPacket* packet = IPPacketFactory::BuildPacket(data, len);
    
    if (packet != nullptr)
    {
        // Deserialize packet from raw data
        int status = packet->Deserialize(data, len);
        
        // Print src/dest
        char addr_str[32];
        if (packet->GetIPVersion() == 4)
        {
            const struct sockaddr_in &src = reinterpret_cast<const struct sockaddr_in&>(packet->GetSourceAddress());
            inet_ntop(AF_INET, &src.sin_addr, addr_str, 32);
            std::cout << "Source Address: " << addr_str << std::endl;
            const struct sockaddr_in &dest = reinterpret_cast<const struct sockaddr_in&>(packet->GetDestinationAddress());
            inet_ntop(AF_INET, &dest.sin_addr, addr_str, 32);
            std::cout << "Destination Address: " << addr_str << std::endl;
        }
        
        if (status == 0)
        {
            // Consult Access Control Module
            bool allowed = _access_control.IsAllowed(reinterpret_cast<IIPPacket*>(packet));
            
            if (allowed)
            {
                if (status == 0)
                {
                    status = _if_manager.SendPacket(reinterpret_cast<IIPPacket*>(packet));
                    
                    switch (status)
                    {
                        case 0:
                        {
                            // Success
                            std::cout << "Message sent successfully" << std::endl;
                            break;
                        }
                        case 1:
                        {
                            // ARP cache miss
                            // Packet queued
                            std::cout << "ARP Cache miss" << std::endl;
                            break;
                        }
                        case 2:
                        {
                            std::cout << "Could not find outgoing interface" << std::endl;
                            break;
                        }
                        default:
                        {
                            // Other error
                            std::cout << "Unknown error (" << status << ")" << std::endl;
                            break;
                        }
                    }
                }
                else
                {
                    std::cout << "Failed to serialize packet" << std::endl;
                }
            }
            else
            {
                std::cout << "Packet Denied" << std::endl;
            }
        }
        else
        {
            std::cout << "Failed to deserialize packet (" << status << ")" << std::endl;
        }
    }
    
    // End of packet lifetime, free memory
    // Delete packet only if packet was created
    if (packet != nullptr)
    {
        delete packet;
    }
    
    // Always free data buffer
    delete data;
}
