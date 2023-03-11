#include "layer3/Layer3Router.hpp"

#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <thread>
#include <arpa/inet.h>
#include <ctime>

#include "layer3/IPPacketFactory.hpp"
#include "layer3/IPUtils.hpp"
#include "logging/Logger.hpp"

Layer3Router::Layer3Router()
    : _if_manager(&_arp_table, &_ip_rte_table, &_napt_table),
#ifndef USE_LOCAL_CONFIG
      _config((uint16_t)3306),
#else
	  _config(),
#endif
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

    Logger::Log(LOG_DEBUG, "Interface Initialization Complete");

    if (status != 0)
    {
        Logger::Log(LOG_FATAL, "Failed to initialize interfaces");
        return INTERFACE_INIT_FAILED;
    }

    // Open all interfaces
    status = _if_manager.OpenAll();
    
    if (status != 0)
    {
        Logger::Log(LOG_FATAL, "Failed to open interfaces");
        return INTERFACE_OPEN_FAILED;
    }

    // Bind receive callback
    Layer3ReceiveCallback callback = std::bind(&Layer3Router::_receive_packet, this, std::placeholders::_1);
    
    NewARPEntryListener arp_listener = std::bind(&Layer3Router::_queue_arp_reply, this, std::placeholders::_1, std::placeholders::_2);
    
    // Listen asynchronously on all interfaces
    status = _if_manager.ListenAll(callback, arp_listener);
    
    if (status != 0)
    {
        Logger::Log(LOG_FATAL, "Failed to listen on interfaces");
        return INTERFACE_LISTEN_FAILED;
    }

    ////////////////////////////////
    //////// Access Control ////////
    ////////////////////////////////

    // Associate configuration module
    // with each access control module
    _access_control.SetConfiguration((IConfiguration*)&_config);
    _null_access.SetConfiguration((IConfiguration*)&_config);
    _access_list.SetConfiguration((IConfiguration*)&_config);

    // Associate ARP table
    // with each access control module
    _access_control.SetARPTable((IARPTable*)&_arp_table);
    _null_access.SetARPTable((IARPTable*)&_arp_table);
    _access_list.SetARPTable((IARPTable*)&_arp_table);

    // Add submodules to central module
    _access_control.AddModule((IAccessControlModule*)&_null_access);
    //_access_control.AddModule((IAccessControlModule*)&_access_list);

    ////////////////////////////////
    /////// Static ACL Setup ///////
    ////////////////////////////////
#ifdef USE_LOCAL_CONFIG
    struct sockaddr_in device1;
    device1.sin_family = AF_INET;
    device1.sin_port = 0;
    inet_pton(AF_INET, "192.168.1.100", &device1.sin_addr);

    struct sockaddr_in device2;
    device2.sin_family = AF_INET;
    device2.sin_port = 0;
    inet_pton(AF_INET, "192.168.2.100", &device2.sin_addr);

    struct sockaddr_in netmask;
    netmask.sin_family = AF_INET;
    netmask.sin_port = 0;
    inet_pton(AF_INET, "255.255.255.0", &netmask.sin_addr);

    const struct sockaddr &_device1 = reinterpret_cast<const sockaddr&>(device1);
    const struct sockaddr &_device2 = reinterpret_cast<const sockaddr&>(device2);
    const struct sockaddr &_netmask = reinterpret_cast<const sockaddr&>(netmask);

    // Allow bi-directional communication
    _config.SetAccessRule(_device1, _netmask, _device2, _netmask, true);
    _config.SetAccessRule(_device2, _netmask, _device1, _netmask, true);

#endif

    return NO_ERROR;
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
        	IIPPacket *pkt;
            _rcv_queue.Dequeue(pkt);
            
            // Pass to packet processing
            _process_packet(pkt);
        }
    }
}

void Layer3Router::_receive_packet(IIPPacket *packet)
{
    // Add to receive queue
    // Ownership of buff pointer transfers
    // to receive queue

    _rcv_queue.Enqueue(packet);
}

void Layer3Router::_process_packet(IIPPacket *packet)
{
    if (packet == nullptr)
    {
    	Logger::Log(LOG_WARNING, "Unexpected nullptr found in layer3 receive queue");
        return;
    }
    std::stringstream sstream;
    
    // Consult Access Control Module
    bool allowed = _access_control.IsAllowed(packet);
    
    if (allowed)
    {
		int status = _if_manager.SendPacket(packet);

		switch (status)
		{
			case NO_ERROR:
			{
				// Success
				Logger::Log(LOG_DEBUG, "Message sent successfully");
				break;
			}
			case ARP_CACHE_MISS_LOCAL:
			case ARP_CACHE_MISS_DEFAULT:
			{
				// ARP cache miss
				Logger::Log(LOG_DEBUG, "ARP Cache Miss");

				outstanding_msg_t msg;
				msg.pkt = packet;
				msg.expires_at = time(NULL) + 5; // 5 seconds

				// Set next hop based on whether the destination is
				// local or via the default gateway
				if (status == ARP_CACHE_MISS_DEFAULT)
				{
					msg.next_hop = _if_manager.GetDefaultGateway(packet->GetIPVersion());
				}
				else
				{
					msg.next_hop = &packet->GetDestinationAddress();
				}

				_outstanding_msgs.push_back(msg);

				// Prevent packet from being freed
				packet = nullptr;
				break;
			}
			case ROUTE_INTERFACE_NOT_FOUND:
			{
				sstream.str("");
				sstream << "Could not find outgoing interface (" << Logger::IPToString(packet->GetDestinationAddress()) << ")";
				Logger::Log(LOG_DEBUG, sstream.str());
				break;
			}
			default:
			{
				sstream.str("");
				sstream << "Miscellaneous error (" << status << ")";
				Logger::Log(LOG_WARNING, sstream.str());
				break;
			}
		}
    }
    else
    {
        // TODO Log more information about denied packet
        Logger::Log(LOG_SECURE, "Packet denied");
    }
    
    // End of packet lifetime, free memory
    // Delete packet only if packet was created
    if (packet != nullptr)
    {
        delete packet;
    }
}

void Layer3Router::_queue_arp_reply(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr)
{
    switch (l3_addr.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in &_l3_addr = reinterpret_cast<const struct sockaddr_in&>(l3_addr);
            struct sockaddr_in *_addr = new struct sockaddr_in;
            
            _addr->sin_family = AF_INET;
            _addr->sin_port = 0;
            memcpy(&_addr->sin_addr, &_l3_addr.sin_addr, 4);
            
            _arp_replies.Enqueue(reinterpret_cast<struct sockaddr*>(_addr));
            
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 &_l3_addr = reinterpret_cast<const struct sockaddr_in6&>(l3_addr);
            struct sockaddr_in6 *_addr = new struct sockaddr_in6;
            
            _addr->sin6_family = AF_INET;
            _addr->sin6_port = 0;
            memcpy(&_addr->sin6_addr, &_l3_addr.sin6_addr, 16);
            
            _arp_replies.Enqueue(reinterpret_cast<struct sockaddr*>(_addr));
            
            break;
        }
    }
}

void Layer3Router::_process_arp_replies()
{
    while (!_arp_replies.IsEmpty())
    {
        struct sockaddr *target_addr;
        _arp_replies.Dequeue(target_addr);
        
        if (target_addr == nullptr)
        {
        	Logger::Log(LOG_DEBUG, "Unexpected nullptr found in ARP reply queue.");
        }

        // Send all outstanding messages to this target address
        for (auto m = _outstanding_msgs.begin(); m < _outstanding_msgs.end(); m++)
        {
            outstanding_msg_t &msg = *m;
            
            if (IPUtils::AddressesAreEqual(*target_addr, *msg.next_hop))
            {
                // Destination address matches, send packet
            	if (msg.pkt != nullptr)
            	{
                    _if_manager.SendPacket(msg.pkt);
                
                    // Free packet memory and remove from outgoing messages
                    delete msg.pkt;
            	}
            	else
            	{
            		Logger::Log(LOG_DEBUG, "Unexpected nullptr found in outgoing messages.");
            	}

                _outstanding_msgs.erase(m);
            }
        }
        
        // Deallocate target address
        switch (target_addr->sa_family)
        {
            case AF_INET:
            {
                struct sockaddr_in *_target_addr = reinterpret_cast<struct sockaddr_in*>(target_addr);
                delete _target_addr;
                break;
            }
            case AF_INET6:
            {
                struct sockaddr_in6 *_target_addr = reinterpret_cast<struct sockaddr_in6*>(target_addr);
                delete _target_addr;
                break;
            }
            default:
            {
                break;
            }
        }
    }
}

void Layer3Router::_drop_stale_messages()
{
    time_t current_time = time(NULL);
    
    for (auto m = _outstanding_msgs.begin(); m < _outstanding_msgs.end(); m++)
    {
        outstanding_msg_t &msg = *m;
        
        // Check if message is expired
        if (current_time > msg.expires_at)
        {
            // Free packet memory and remove from outgoing messages
        	if (msg.pkt != nullptr)
        	{
                delete msg.pkt;
                _outstanding_msgs.erase(m);
        	}
        	else
        	{
        		Logger::Log(LOG_DEBUG, "Unexpected nullptr found when dropping stale queued messages.");
        	}
        }
    }
}
