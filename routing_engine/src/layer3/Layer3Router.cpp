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
#include "keys/KeyUtils.hpp"

Layer3Router::Layer3Router()
    : _ipsec_utils(&_key_manager),
	  _if_manager(&_arp_table, &_ip_rte_table, &_napt_table, &_ipsec_utils),
#ifndef USE_LOCAL_CONFIG
      _config((uint16_t)3306),
#else
	  _config(),
#endif
      _access_control(),
      _rcv_queue(),
      _exiting(false),
	  _key_manager(),
	  _next_monitor_time(0)
{
}

Layer3Router::~Layer3Router()
{
}

int Layer3Router::Initialize()
{
	std::stringstream sstream;
    int status;

    ////////////////////////////////////
    //////// Layer 2 Interfaces ////////
    ////////////////////////////////////

    // Initialize Ethernet Interfaces Only
    status = _if_manager.InitializeInterfaces(IM_IF_ETHERNET);

    Logger::Log(LOG_INFO, "Interface Initialization Complete");

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
    
    if (status != NO_ERROR)
    {
        Logger::Log(LOG_FATAL, "Failed to listen on interfaces");
        return INTERFACE_LISTEN_FAILED;
    }

    // Initialize Key Manager
#ifndef USE_LOCAL_KEYS
    status = _key_manager.Initialize();

    if (status != NO_ERROR)
    {
    	Logger::Log(LOG_FATAL, "Failed to initialize key manager");
    	return status;
    }
    Logger::Log(LOG_INFO, "Initialized Key Manager");

    // Add manual host
    struct sockaddr_in host;
    host.sin_family = AF_INET;
    host.sin_port = 0;
    inet_pton(AF_INET, "192.168.1.2", &host.sin_addr);

    status = _key_manager.AddHost(reinterpret_cast<struct sockaddr&>(host));

    if (status != NO_ERROR)
    {
    	sstream.str("");
    	sstream << "Failed to add host: " << Logger::IPToString(reinterpret_cast<struct sockaddr&>(host));
    	Logger::Log(LOG_ERROR, sstream.str());
    }
#else
    // Add manually-configured keys
    struct sockaddr_in src;
    src.sin_family = AF_INET;
    src.sin_port = 0;
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_port = 0;

    const std::string device1key = "0ea5f191085596967637d4de154178728a0c8ad237592738f479b56d265ff716";
    const std::string device2key = "d6a0d1a78a97289b32e607f49f5d2c45a389b7b387808897e8ee568326bb8955";
    const std::string device3key = "b8110a936705fd535fdc8c1698e8e2e7ede71db852b78ebd677a7d0c14b4e729";

    const size_t KEY_LEN = 32;
    uint8_t key[KEY_LEN];

    // Device 1
    KeyUtils::FromHexString(device1key, key, KEY_LEN);
    inet_pton(AF_INET, "192.168.1.2", &src.sin_addr);
    inet_pton(AF_INET, "192.168.1.1", &dst.sin_addr);
    _key_manager.AddKey(1000, reinterpret_cast<struct sockaddr&>(src), reinterpret_cast<struct sockaddr&>(dst), key, KEY_LEN);
    _key_manager.AddKey(1001, reinterpret_cast<struct sockaddr&>(dst), reinterpret_cast<struct sockaddr&>(src), key, KEY_LEN);

    // Device 2
    KeyUtils::FromHexString(device2key, key, KEY_LEN);
    inet_pton(AF_INET, "192.168.1.6", &src.sin_addr);
    inet_pton(AF_INET, "192.168.1.5", &dst.sin_addr);
    _key_manager.AddKey(2000, reinterpret_cast<struct sockaddr&>(src), reinterpret_cast<struct sockaddr&>(dst), key, KEY_LEN);
    _key_manager.AddKey(2001, reinterpret_cast<struct sockaddr&>(dst), reinterpret_cast<struct sockaddr&>(src), key, KEY_LEN);

    // Device 3
    KeyUtils::FromHexString(device3key, key, KEY_LEN);
    inet_pton(AF_INET, "192.168.1.10", &src.sin_addr);
    inet_pton(AF_INET, "192.168.1.9", &dst.sin_addr);
    _key_manager.AddKey(3000, reinterpret_cast<struct sockaddr&>(src), reinterpret_cast<struct sockaddr&>(dst), key, KEY_LEN);
    _key_manager.AddKey(3001, reinterpret_cast<struct sockaddr&>(dst), reinterpret_cast<struct sockaddr&>(src), key, KEY_LEN);

#endif

    ////////////////////////////////
    //////// Access Control ////////
    ////////////////////////////////
    // Associate configuration module
    // with each access control module
    _access_control.SetConfiguration((IConfiguration*)&_config);
    _null_access.SetConfiguration((IConfiguration*)&_config);
    _access_list.SetConfiguration((IConfiguration*)&_config);
    _message_auth.SetConfiguration((IConfiguration*)&_config);
    _replay_detect.SetConfiguration((IConfiguration*)&_config);

    // Associate ARP table
    // with each access control module
    _access_control.SetARPTable((IARPTable*)&_arp_table);
    _null_access.SetARPTable((IARPTable*)&_arp_table);
    _access_list.SetARPTable((IARPTable*)&_arp_table);
    _message_auth.SetARPTable((IARPTable*)&_arp_table);
    _replay_detect.SetARPTable((IARPTable*)&_arp_table);

    // Associate IPsec Utils
    _access_control.SetIPSecUtils((IIPSecUtils*)&_ipsec_utils);
    _null_access.SetIPSecUtils((IIPSecUtils*)&_ipsec_utils);
    _access_list.SetIPSecUtils((IIPSecUtils*)&_ipsec_utils);
    _message_auth.SetIPSecUtils((IIPSecUtils*)&_ipsec_utils);
    _replay_detect.SetIPSecUtils((IIPSecUtils*)&_ipsec_utils);

    // Add submodules to central module
    _access_control.AddModule((IAccessControlModule*)&_null_access);
    _access_control.AddModule((IAccessControlModule*)&_access_list);

#ifndef DISABLE_AUTH
    _access_control.AddModule((IAccessControlModule*)&_replay_detect);
    _access_control.AddModule((IAccessControlModule*)&_message_auth);
#endif

    ////////////////////////////////
    /////// Static ACL Setup ///////
    ////////////////////////////////
#ifdef USE_LOCAL_CONFIG
    // Alice
    struct sockaddr_in device1;
    device1.sin_family = AF_INET;
    device1.sin_port = 0;
    inet_pton(AF_INET, "192.168.1.2", &device1.sin_addr);

    // Bob
    struct sockaddr_in device2;
    device2.sin_family = AF_INET;
    device2.sin_port = 0;
    inet_pton(AF_INET, "192.168.1.10", &device2.sin_addr);

    struct sockaddr_in netmask;
    netmask.sin_family = AF_INET;
    netmask.sin_port = 0;
    inet_pton(AF_INET, "255.255.255.252", &netmask.sin_addr);

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
	std::stringstream sstream;
    while (!_exiting)
    {
        // Check for changes in configuration
        while (_config.LocalIsOutdated())
        {
            // Command Update
            _config.UpdateLocal();

            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        time_t current_time = time(NULL);
        if (_next_monitor_time < current_time)
        {
        	_next_monitor_time = current_time + 1;
        	_if_manager.SendMonitorReport();
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
    std::stringstream sstream;
    if (packet == nullptr)
    {
        return;
    }

    struct sockaddr_storage local_ip;
    ILayer2Interface *_if = _ip_rte_table.GetInterface(packet->GetDestinationAddress(), local_ip);
    if (_if == nullptr) // Null return value means use default interface
    {
    	packet->SetIsToDefaultInterface(true);
    }

    // Consult Access Control Modules
    bool allowed = _access_control.IsAllowed(packet);
    
    if (allowed)
    {
		int status = _if_manager.SendPacket(packet);

		switch (status)
		{
			case NO_ERROR:
			{
				// Success
				break;
			}
			case ARP_CACHE_MISS_LOCAL:
			case ARP_CACHE_MISS_DEFAULT:
			{
				// ARP cache miss
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
				break;
			}
			default:
			{
				break;
			}
		}
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
        }
    }
}
