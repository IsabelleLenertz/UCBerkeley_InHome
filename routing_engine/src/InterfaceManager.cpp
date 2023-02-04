#include "InterfaceManager.hpp"
#include <pcap/pcap.h>

InterfaceManager::InterfaceManager()
    : _interfaces()
{
}

InterfaceManager::~InterfaceManager()
{
    for (auto _if = _interfaces.begin(); _if < _interfaces.end(); _if++)
    {
        ILayer2Interface* _interface = *_if;
        
        delete _interface;
    }
}

int InterfaceManager::InitializeInterfaces(int flags)
{
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int status;
    
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
    	if (node->flags & PCAP_IF_LOOPBACK)
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
        }
    
        node = node->next;
    }
    
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


