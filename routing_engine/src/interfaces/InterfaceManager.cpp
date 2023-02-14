#include "interfaces/InterfaceManager.hpp"
#include "layer2/EtherUtils.hpp"
#include "layer3/IPUtils.hpp"

#include <pcap/pcap.h>

#include <iomanip>
#include <iostream>
#include <cstring>
#include <fstream>

std::ostream& operator<<(std::ostream &lhs, const struct sockaddr *addr)
{
    switch (addr->sa_family)
    {
        case AF_INET:
        {
            // Note: first 2 bytes are port
            for (int i = 2; i < 5; i++)
            {
                lhs << +(uint8_t)addr->sa_data[i] << ".";
            }
            lhs << +(uint8_t)addr->sa_data[5];
            
            break;
        }
        case AF_INET6:
        {
            lhs << std::hex;
            
            for (int i = 6; i < 20; i += 2)
            {
                lhs << std::setw(2) << std::setfill('0') << +(uint8_t)addr->sa_data[i] << std::setw(2) << std::setfill('0') << +(uint8_t)addr->sa_data[i + 1] << ":";
            }
            lhs << std::setw(2) << std::setfill('0') << +(uint8_t)addr->sa_data[20] << std::setw(2) << std::setfill('0') << +(uint8_t)addr->sa_data[21];
            
            lhs << std::dec;
            break;
        }
        default:
        {
            std::cout << "Unknown Address Family: " << addr->sa_family;
            break;
        }
    }
    
    return lhs;
}

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

int InterfaceManager::ListenAll(Layer2ReceiveCallback& callback)
{
    int status = 0;
    
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface *_interface = *_if;
        int tmp = _interface->Listen(callback, true);
        
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


int InterfaceManager::SendPacket(const uint8_t *data, size_t len)
{
    return 1;
}

void InterfaceManager::_registerAddresses(ILayer2Interface* _if, pcap_if_t *pcap_if)
{
    // Convert null-terminated name string to std::string
    std::string name(pcap_if->name);
    
    // Get MAC string from system files
    std::fstream file;
    file.open("sys/class/net/" + name + "/address", std::ios::in);
    char mac_str[18];
    
    if (!file.is_open())
    {
        // Error opening file. Cannot continue
        return;
    }
    file.getline(mac_str, 18);
    
    // Convert MAC string to ether_addr
    struct ether_addr mac_addr;
    int status = EtherUtils::AddressFromString(mac_str, mac_addr);
    
    if (status != 0)
    {
        // Error parsing MAC address. Cannot continue.
        return;
    }
    
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
