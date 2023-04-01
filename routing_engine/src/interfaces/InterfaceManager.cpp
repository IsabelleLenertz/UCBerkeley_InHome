#include "interfaces/InterfaceManager.hpp"
#include "layer2/EtherUtils.hpp"
#include "layer3/IPUtils.hpp"
#include "layer3/IPPacketFactory.hpp"

#include <pcap/pcap.h>

#include <sstream>
#include <cstring>
#include <fstream>
#include <arpa/inet.h>

#include "logging/Logger.hpp"

InterfaceManager::InterfaceManager(IARPTable *arp_table, IRoutingTable *ip_rte_table, NAPTTable *napt_table, IIPSecUtils *ipsec_utils)
    : _interfaces(),
      _arp_table(arp_table),
      _ip_rte_table(ip_rte_table),
	  _napt_table(napt_table),
	  _ipsec_utils(ipsec_utils),
	  _v4_gateway_set(false),
	  _v6_gateway_set(false),
	  _default_if(nullptr)
{
	memset(&_v4_gateway, 0, sizeof(_v4_gateway));
	memset(&_v6_gateway, 0, sizeof(_v6_gateway));
}

InterfaceManager::~InterfaceManager()
{
    // Iterate through and detete all interfaces
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        delete *_if;
    }
}

int InterfaceManager::InitializeInterfaces(int flags)
{
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int status = ERROR_UNSET;
    
    // Use PCAP to find all available devices
    status = pcap_findalldevs(&alldevsp, errbuf);
    
    if (status != 0)
    {
    	Logger::Log(LOG_FATAL, "Failed to get available interfaces.");
    	Logger::Log(LOG_FATAL, (char*)errbuf);
        return INTERFACE_INIT_FAILED;
    }
    
    pcap_if_t *node = alldevsp;
    while (node != nullptr)
    {
        bool valid = false;
        
        // Compare interface type with flags
        if (strcmp("any", node->name) == 0)
        {
            valid = false;
        }
        else if (node->flags & PCAP_IF_LOOPBACK)
        {
            if (flags & IM_IF_LOOPBACK)
            {
                valid = true;
            }
        }
        else if (node->flags & PCAP_IF_WIRELESS)
        {
            if (flags & IM_IF_WIRELESS)
            {
                valid = true;
            }
        }
        else
        {
            if (flags & IM_IF_ETHERNET)
            {
                valid = true;
            }
        }
        
        // If interface is down and that is not allowed,
        // mark interface as invalid
        if (!(node->flags & PCAP_IF_UP) && !(flags & IM_IF_INC_DOWN))
        {
            valid = false;
        }
        
        // If valid flag is still set, add the interface
        if (valid)
        {
            ILayer2Interface *_if;
            
            if (node->flags & PCAP_IF_WIRELESS)
            {
                _if = new WiFiInterface(node->name, _arp_table);
            }
            else
            {
                _if = new EthernetInterface(node->name, _arp_table);
            }
            
            // Register
            _if->SetIPAddressQueryMethod(std::bind(&IRoutingTable::IsOwnedByInterface, _ip_rte_table, std::placeholders::_1, std::placeholders::_2));
            
            // Add interface to list
            _interfaces.push_back(_if);
            
            // Register interface addresses
            _registerAddresses(_if, node);
        }
    
        node = node->next;
    }
    
    pcap_freealldevs(alldevsp);
    
    // Initialize monitor
    status = _monitor.Initialize(12001);

    if (status != NO_ERROR)
    {
    	return status;
    }

    return 0;
}

int InterfaceManager::OpenAll()
{
    int status = NO_ERROR;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Open();
        
        if (tmp != 0)
        {
            status = INTERFACE_OPEN_FAILED;
        }
    }
    
    return status;
}

int InterfaceManager::CloseAll()
{
    int status = NO_ERROR;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Close();
        
        if (tmp != 0)
        {
            status = INTERFACE_CLOSE_FAILED;
        }
    }
    
    return status;
}

int InterfaceManager::ListenAll(Layer3ReceiveCallback callback, NewARPEntryListener arp_listener)
{
    int status = NO_ERROR;
    
    _callback = callback;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        
        int tmp = _interface->Listen(
            std::bind(&InterfaceManager::ReceiveLayer2Data, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), arp_listener, true);
        
        if (tmp != 0)
        {
            status = INTERFACE_LISTEN_FAILED;
        }
    }
    
    return status;
}

int InterfaceManager::StopListenAll()
{
    int status = NO_ERROR;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->StopListen();
        
        if (tmp != 0)
        {
            status = INTERFACE_STOP_LISTEN_FAILED;
        }
    }

    return status;
}


int InterfaceManager::SendPacket(IIPPacket *packet)
{
	std::stringstream sstream;
	int status = NO_ERROR;

	if (!packet->GetIsFromDefaultInterface() && !packet->GetIsToDefaultInterface())
	{
		// Update authentication header data
		status = _ipsec_utils->TransformAuthHeader(packet);

		if (status != NO_ERROR)
		{
			return status;
		}
	}

	// Locate the outgoing interface based on destination address
    struct sockaddr_storage local_ip;
	ILayer2Interface *_if = _ip_rte_table->GetInterface(packet->GetDestinationAddress(), local_ip);

	// Set gateway based on IP version
	const struct sockaddr &gateway = (packet->GetIPVersion() == 4) ?
			reinterpret_cast<const struct sockaddr&>(_v4_gateway) :
			reinterpret_cast<const struct sockaddr&>(_v6_gateway);

	const struct sockaddr &gateway_local = (packet->GetIPVersion() == 4) ?
			reinterpret_cast<const struct sockaddr&>(_v4_gateway_local) :
			reinterpret_cast<const struct sockaddr&>(_v6_gateway_local);

	// If nullptr is returned for interface, use default
	if (_if == nullptr)
	{
		_if = _default_if;
	}

	// Set local IP based on whether the egress interface is the default interface
	const struct sockaddr &_local_ip = _if->GetIsDefault() ?
			reinterpret_cast<const struct sockaddr&>(gateway_local) :
			reinterpret_cast<const struct sockaddr&>(local_ip);

	// Set destination address based on whether the egress
	// interface is the default interface (used to resolve MAC address)
	// Default: Use default gateway
	// Otherwise: Use destination address
	const struct sockaddr &dst_addr = _if->GetIsDefault() ? gateway : packet->GetDestinationAddress();

	// If egress interface is default interface,
	// need to perform network address translation
	if (_if->GetIsDefault())
	{
		Logger::Log(LOG_DEBUG, "NAT required");
		status = _napt_table->TranslateToExternal(packet, _local_ip);

		if (status != NO_ERROR)
		{
			return status;
		}
	}

	uint16_t len = SEND_BUFFER_SIZE;
	status = packet->Serialize(_send_buff, len);

	if (status != NO_ERROR)
	{
		return status;
	}

	// Increment counters
	_if->Stats().tx_count++;
	switch (packet->GetProtocol())
	{
		case IPPROTO_ICMP:
		{
			_if->Stats().icmp_tx_count++;
			break;
		}
		case IPPROTO_TCP:
		{
			_if->Stats().tcp_tx_count++;
			break;
		}
		case IPPROTO_UDP:
		{
			_if->Stats().udp_tx_count++;
			break;
		}
		case IPPROTO_AH:
		{
			_if->Stats().ipsec_tx_count++;
			break;
		}
		default:
		{
			break;
		}
	}

	status = _if->SendPacket(_local_ip, dst_addr, _send_buff, len);

	return status;
}

void InterfaceManager::_registerAddresses(ILayer2Interface* _if, pcap_if_t *pcap_if)
{
    std::stringstream sstream;
    sstream << "Registering interface: " << _if->GetName();
    Logger::Log(LOG_INFO, sstream.str());

    struct ether_addr mac_addr;
    
    int status = EtherUtils::GetMACAddress(pcap_if->name, mac_addr);

    if (status != 0)
    {
        // Error parsing MAC address. Cannot continue.
        return;
    }
    
    // Associate MAC address with the interface
    _if->SetMACAddress(mac_addr);
    
    // Iterate through all addresses for this interface
    pcap_addr_t *node = pcap_if->addresses;
    while (node != nullptr)
    {
        // Note that it is possible for an address struct
        // to not include a netmask
        if (node->netmask != nullptr)
        {
            const struct sockaddr &ip_addr = *node->addr;
            const struct sockaddr &netmask = *node->netmask;
            
            // Register with ARP table
            _arp_table->SetARPEntry(ip_addr, mac_addr);
            
            // Register subnet on interface
            _ip_rte_table->AddSubnetAssociation(_if, ip_addr, netmask);

            char ip_str[64];

            switch (ip_addr.sa_family)
            {
				case AF_INET:
				{
					if (!_v4_gateway_set)
					{
						const struct sockaddr_in &_ip_addr = reinterpret_cast<const struct sockaddr_in&>(ip_addr);
						struct sockaddr_in gateway;
						gateway.sin_family = AF_INET;
						gateway.sin_port = 0;
						memcpy(&gateway.sin_addr, &_ip_addr.sin_addr, 4);
						uint8_t *addr_ptr = (uint8_t*)&gateway.sin_addr;
						*(addr_ptr + 3) = 1;

						inet_ntop(AF_INET, &gateway.sin_addr, ip_str, 64);
						inet_ntop(AF_INET, &_ip_addr.sin_addr, ip_str, 64);

						// TODO Fix
						// Overwrite gateway address
						inet_pton(AF_INET, "10.0.2.2", &gateway.sin_addr);

						const struct sockaddr &_gateway = reinterpret_cast<const struct sockaddr&>(gateway);
						SetDefaultGateway(_gateway, ip_addr);
						_if->SetAsDefault();
						_default_if = _if;
					}
					break;
				}
				case AF_INET6:
				{
					break;
				}
            }
        }
        
        node = node->next;
    }
}

ILayer2Interface* InterfaceManager::GetInterfaceFromName(const char *name)
{
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        if (strcmp(name, (*_if)->GetName()) == 0)
        {
            return *_if;
        }
    }
    
    return nullptr;
}

void InterfaceManager::ReceiveLayer2Data(ILayer2Interface *_if, const uint8_t *data, size_t len)
{
	std::stringstream sstream;
    // Indicates whether the packet was transferred to layer 3
    bool transferred = false;
    
    IIPPacket *packet = IPPacketFactory::BuildPacket(data, len);
    
    int status = packet->Deserialize(data, len);
    
    if (status == 0)
    {
    	// Increment counters
    	_if->Stats().rx_count++;
    	switch (packet->GetProtocol())
    	{
    		case IPPROTO_ICMP:
    		{
    			_if->Stats().icmp_rx_count++;
    			break;
    		}
    		case IPPROTO_TCP:
    		{
    			_if->Stats().tcp_rx_count++;
    			break;
    		}
    		case IPPROTO_UDP:
    		{
    			_if->Stats().udp_rx_count++;
    			break;
    		}
    		case IPPROTO_AH:
    		{
    			_if->Stats().ipsec_rx_count++;
    			break;
    		}
    		default:
    		{
    			break;
    		}
    	}

		// If the ingress interface is the default interface,
		// then network address translation must be performed
		if (_if->GetIsDefault())
		{
			// Mark the packet as received on the default interface
			packet->SetIsFromDefaultInterface(true);

			status = _napt_table->TranslateToInternal(packet);

			if (status != NO_ERROR)
			{
				sstream.str("");
				sstream << "Network address translation failed: (" << status << ")";

				Logger::Log(LOG_ERROR, sstream.str());
			}
		}
		else
		{
			// Mark the packet as not received on the default interface
			packet->SetIsFromDefaultInterface(false);
		}

		// If network address translation was attempted, it
		// must have been successfuly in order to pass the
		// packet to the routing engine
		if (status == NO_ERROR)
		{
			// Pass to routing engine. Routing engine is now responsible for memory management.
			_callback(packet);
			transferred = true;
		}
    }
    
    if (!transferred)
    {
        // Packet was not transferred. Free memory.
        delete packet;
    }
}

void InterfaceManager::SetDefaultGateway(const struct sockaddr &gateway_ip, const struct sockaddr &local_ip)
{
	char ipstr[64];
	std::stringstream sstream;

	switch (gateway_ip.sa_family)
	{
		case AF_INET:
		{
			const struct sockaddr_in _gateway_ip = reinterpret_cast<const struct sockaddr_in&>(gateway_ip);
			_v4_gateway.sin_family = AF_INET;
			_v4_gateway.sin_port = 0;
			memcpy(&_v4_gateway.sin_addr, &_gateway_ip.sin_addr, 4);

			const struct sockaddr_in &_local_ip = reinterpret_cast<const struct sockaddr_in&>(local_ip);
			_v4_gateway_local.sin_family = AF_INET;
			_v4_gateway_local.sin_port = 0;
			memcpy(&_v4_gateway_local.sin_addr, &_local_ip.sin_addr, 4);

			_v4_gateway_set = true;
			break;
		}
		case AF_INET6:
		{
			const struct sockaddr_in6 _gateway_ip = reinterpret_cast<const struct sockaddr_in6&>(gateway_ip);
			_v6_gateway.sin6_family = AF_INET6;
			_v6_gateway.sin6_port = 0;
			_v6_gateway.sin6_flowinfo = 0;
			memcpy(&_v6_gateway.sin6_addr, &_gateway_ip.sin6_addr, 16);

			const struct sockaddr_in6 _local_ip = reinterpret_cast<const struct sockaddr_in6&>(local_ip);
			_v6_gateway_local.sin6_family = AF_INET6;
			_v6_gateway_local.sin6_port = 0;
			_v6_gateway_local.sin6_flowinfo = 0;
			memcpy(&_v6_gateway_local.sin6_addr, &_local_ip.sin6_addr, 16);

			_v6_gateway_set = true;
			break;
		}
		default:
		{
			break;
		}
	}
}

const struct sockaddr *InterfaceManager::GetDefaultGateway(int version)
{
	struct sockaddr *result = nullptr;

	switch (version)
	{
		case 4:
		{
			result = reinterpret_cast<struct sockaddr*>(&_v4_gateway);
			break;
		}
		case 6:
		{
			result = reinterpret_cast<struct sockaddr*>(&_v6_gateway);
			break;
		}
		default:
		{
			break;
		}
	}
}

void InterfaceManager::SendMonitorReport()
{
	InterfaceStatsPacket pkt;

	for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
	{
		ILayer2Interface *_interface = *_if;

		pkt.SetInterfaceData(_interface->GetName(), _interface->Stats());
	}

	int status = _monitor.SendPacket(reinterpret_cast<MonitorPacketBase*>(&pkt));
}
