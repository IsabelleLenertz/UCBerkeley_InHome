#include "interfaces/InterfaceManager.hpp"
#include "layer2/EtherUtils.hpp"
#include "layer3/IPUtils.hpp"

#include <pcap/pcap.h>

#include <sstream>
#include <cstring>
#include <fstream>

#include "logging/Logger.hpp"

InterfaceManager::InterfaceManager(IARPTable *arp_table, IRoutingTable *ip_rte_table)
    : _interfaces(),
      _arp_table(arp_table),
      _ip_rte_table(ip_rte_table)
{
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
    int status;
    
    // Use PCAP to find all available devices
    status = pcap_findalldevs(&alldevsp, errbuf);
    
    if (status != 0)
    {
        return status;
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
    
    return 0;
}

int InterfaceManager::OpenAll()
{
    int status = 0;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Open();
        
        if (tmp != 0)
        {
            status = 1;
        }
    }
    
    return status;
}

int InterfaceManager::CloseAll()
{
    int status = 0;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Close();
        
        if (tmp != 0)
        {
            status = 1;
        }
    }
    
    return status;
}

int InterfaceManager::ListenAll(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener)
{
    int status = 0;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Listen(callback, arp_listener, true);
        
        if (tmp != 0)
        {
            status = 1;
        }
    }
    
    return status;
}

int InterfaceManager::StopListenAll()
{
    int status = 0;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->StopListen();
        
        if (tmp != 0)
        {
            status = 1;
        }
    }
    
    return status;
}


int InterfaceManager::SendPacket(IIPPacket *packet)
{
    const struct sockaddr &src_addr = packet->GetSourceAddress();
    const struct sockaddr &dst_addr = packet->GetDestinationAddress();
    int status = 0;
    
    // Locate the outgoing interface based on destination address
    const struct sockaddr *local_ip = nullptr;
    ILayer2Interface *_if = _ip_rte_table->GetInterface(dst_addr, &local_ip);
    
    if (_if == nullptr)
    {
        // Interface not found
        return 2;
    }
    
    uint16_t len = SEND_BUFFER_SIZE;
    status = packet->Serialize(_send_buff, len);
    
    if (status != 0)
    {
        return 3;
    }
    
    status = _if->SendPacket(*local_ip, dst_addr, _send_buff, (size_t)len);
    
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
            struct sockaddr subnet;
            
            // Calculate subnet ID
            IPUtils::GetSubnetID(ip_addr, netmask, subnet);
            
            // Register with ARP table
            _arp_table->SetARPEntry(ip_addr, mac_addr);
            
            // Register subnet on interface
            _ip_rte_table->AddSubnetAssociation(_if, subnet, netmask);
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

