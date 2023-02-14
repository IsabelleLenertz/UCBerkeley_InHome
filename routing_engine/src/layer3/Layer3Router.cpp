#include "layer3/Layer3Router.hpp"

#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <thread>

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
    std::cout << "----------------" << std::endl;
    std::cout << len << " bytes received at Layer 3" << std::endl;
    
    std::cout << std::hex;
    
    int i;
    for (i = 0; i < len; i++)
    {
        std::cout << std::setw(2) << std::setfill('0') << +data[i];
        if ((i + 1) % 8 == 0)
        {
            std::cout << std::endl;
        }
        else
        {
            std::cout << " ";
        }
    }
    
    if ((i) % 8 != 0)
    {
        std:: cout << std::endl;
    }

    std::cout << "----------------" << std::endl;
    std::cout << std::dec;
    
    // TODO Need to switch to abstract factory pattern
    // Temporary: Assume IPv4 packet
    IPv4Packet *packet = static_cast<IPv4Packet*>(IPPacketFactory::BuildPacket(data, len));
    
    if (packet != nullptr)
    {
        // Deserialize packet from raw data
        int status = packet->Deserialize(data, len);
        
        if (status == 0)
        {
            // Consult Access Control Module
            bool allowed = _access_control.IsAllowed(static_cast<IIPPacket*>(packet));
            
            if (allowed)
            {
                // Packet is allowed, send
                uint16_t _len = SEND_BUFFER_SIZE;
                status = packet->Serialize(_send_buff, _len);
                
                if (status == 0)
                {
                    status = _if_manager.SendPacket(_send_buff, _len);
                    
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
                        default:
                        {
                            // Other error
                            std::cout << "Unknown error" << std::endl;
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
