#include "layer2/EthernetInterface.hpp"
#include "logging/Logger.hpp"

#include <net/ethernet.h>
#include <cstring>
#include <arpa/inet.h>

#include <iomanip>
#include <sstream>

EthernetInterface::EthernetInterface(const char *if_name, IARPTable *arp_table)
    : _handle(nullptr),
      _thread(),
      _arp_table(arp_table),
      _callback(),
      _arp_listener(),
      _owns_address(),
	  _is_default(false)
{
    memset(error_buffer, 0, sizeof(error_buffer));
    memset(&_mac_addr, 0, sizeof(_mac_addr));
    memset(_frame_buffer, 0, sizeof(_frame_buffer));
    
    _if_name = std::string(if_name);
}

EthernetInterface::~EthernetInterface()
{
}

int EthernetInterface::Open()
{
    std::stringstream sstream;
    _handle = pcap_open_live(
        _if_name.c_str(), // Interface to open
        BUFSIZ,           // Maximum number of bytes per packet
        0,                // Not in promiscuous mode
        10,               // Packet buffer timeout
        error_buffer);    // Error output buffer
    
    if (_handle == nullptr)
    {
    	sstream << "Failed to Open Interface: " << GetName();
    	Logger::Log(LOG_FATAL, sstream.str());
    	Logger::Log(LOG_FATAL, (char*)error_buffer);
        return INTERFACE_OPEN_FAILED; // Could not open interface
    }
    
    sstream << "Opened interface: " << this->GetName();
    Logger::Log(LOG_DEBUG, sstream.str());

    return NO_ERROR;
}

int EthernetInterface::Close()
{
    // If still listening, stop
    StopListen();
    
    // Close the handle
    if (_handle != nullptr)
    {
        pcap_close(_handle);
    }
    
    return NO_ERROR;
}

int EthernetInterface::Listen(Layer2ReceiveCallback callback, NewARPEntryListener arp_listener, bool async)
{
	int status = ERROR_UNSET;

    // Register the callback
    _callback = callback;
    _arp_listener = arp_listener;


    std::stringstream sstream;
    sstream << "ether dst ";

    sstream << std::hex;
    for (int i = 0; i < ETH_ALEN; i++)
    {
    	sstream << std::setw(2) << std::setfill('0') << +_mac_addr.ether_addr_octet[i];
    	if (i < ETH_ALEN - 1)
    	{
    		sstream << ":";
    	}
    }
    sstream << " or ether broadcast" << std::endl;

    struct bpf_program filter_pgm;

    status = pcap_compile(_handle, &filter_pgm, sstream.str().c_str(), 1, PCAP_NETMASK_UNKNOWN);

    if (status != 0)
    {
    	Logger::Log(LOG_FATAL, "Failed to compile filter");
    	Logger::Log(LOG_FATAL, sstream.str());
    	Logger::Log(LOG_FATAL, pcap_geterr(_handle));
    	return COMPILE_FILTER_FAILED;
    }

    status = pcap_setfilter(_handle, &filter_pgm);

    if (status != 0)
    {
    	Logger::Log(LOG_FATAL, "Failed to set filter");
    	return SET_FILTER_FAILED;
    }

    Logger::Log(LOG_DEBUG, "Filter Set Successfully");

    if (async)
    {
        // If async, start up a thread on which
        // to call the capture loop
        _thread = std::thread(std::bind(&EthernetInterface::_captureLoop, this));
    }
    else
    {
        // If not async, capture on current thread
        _captureLoop();
    }

    return NO_ERROR;
}

int EthernetInterface::StopListen()
{
    // Check if the thread is running
    if (_thread.joinable())
    {
        // Force thread termination
        pcap_breakloop(_handle);
        
        // Wait for thread to complete
        _thread.join();
    }
    
    return NO_ERROR;
}

int EthernetInterface::SendPacket(const struct sockaddr &l3_local_addr, const struct sockaddr &l3_dest_addr, const uint8_t *data, size_t len)
{
    std::scoped_lock { _mutex };

    if (_is_default)
    {
    	char addr_str[64];
    	std::stringstream sstream;

    	const struct sockaddr_in _l3_dest_addr = reinterpret_cast<const struct sockaddr_in&>(l3_dest_addr);
    	inet_ntop(AF_INET, &_l3_dest_addr.sin_addr, addr_str, 64);

    	sstream << "Sending to Default Gateway: " << addr_str;
    	Logger::Log(LOG_DEBUG, sstream.str());
    }

    int status = NO_ERROR;
    
    if (len + ETHER_HDR_LEN > MAX_FRAME_LEN)
    {
    	return 4;
    }

    // Get destination address from ARP table
    bool hit;
    struct ether_addr l2_dest_addr;
    hit = _arp_table->GetL2Address(l3_dest_addr, l2_dest_addr);
    
    if (!hit)
    {
    	Logger::Log(LOG_DEBUG, "ARP Cache Miss");

        // Set destination address to broadcast address
        memcpy(&l2_dest_addr, &BROADCAST_MAC, ETH_ALEN);
        
        // Construct ARP request
        ARPMessage request;
        request.SetMessageType(ARP_MSG_TYPE_REQUEST);
        
        // Set HW parameters
        request.SetHWType(ARP_HW_TYPE_ETHERNET);
        request.SetHWAddrLen(6);
        request.SetSenderHWAddress((uint8_t*)&_mac_addr, ETH_ALEN);
        request.SetTargetHWAddress((uint8_t*)&BLANK_MAC, ETH_ALEN);
        
        // Set Protocol parameters (IPv4 or IPv6)
        switch (l3_local_addr.sa_family)
        {
            case AF_INET:
            {
                request.SetProtocolType(ARP_PROTO_TYPE_IPV4);
                request.SetProtoAddrLen(4);
                
                const struct sockaddr_in& _l3_local_addr = reinterpret_cast<const struct sockaddr_in&>(l3_local_addr);
                const struct sockaddr_in& _l3_dest_addr = reinterpret_cast<const struct sockaddr_in&>(l3_dest_addr);
                
                request.SetSenderProtoAddress((uint8_t*)&_l3_local_addr.sin_addr, 4);
                request.SetTargetProtoAddress((uint8_t*)&_l3_dest_addr.sin_addr, 4);
                
                break;
            }
            case AF_INET6:
            {
                request.SetProtocolType(ARP_PROTO_TYPE_IPV6);
                request.SetProtoAddrLen(16);
                
                const struct sockaddr_in6& _l3_local_addr = reinterpret_cast<const struct sockaddr_in6&>(l3_local_addr);
                const struct sockaddr_in6& _l3_dest_addr = reinterpret_cast<const struct sockaddr_in6&>(l3_dest_addr);
                
                request.SetSenderProtoAddress((uint8_t*)&_l3_local_addr.sin6_addr, 16);
                request.SetTargetProtoAddress((uint8_t*)&_l3_dest_addr.sin6_addr, 16);
                break;
            }
            default:
            {
            	Logger::Log(LOG_DEBUG, "ARP: Unrecognized Address Family");
                break;
            }
        }
        
        // Serialize ARP Message into frame payload
        // Also overwrites payload length
        len = MAX_FRAME_LEN;
        status = request.Serialize(_frame_buffer + ETHER_HDR_LEN, len);
        
        if (status == NO_ERROR)
        {
        	if (!_is_default)
        	{
				// Indicate an ARP miss
				status = ARP_CACHE_MISS_LOCAL;
        	}
        	else
        	{
        		status = ARP_CACHE_MISS_DEFAULT;
        	}
        }
    }
    else
    {
    	Logger::Log(LOG_DEBUG, "ARP Cache Hit");

        // Copy payload
        memcpy(_frame_buffer + ETHER_HDR_LEN, data, len);
    }
    
    // Only send if no error has occurred up to this point
    if (status == NO_ERROR || status == ARP_CACHE_MISS_LOCAL || status == ARP_CACHE_MISS_DEFAULT)
    {
        // Populate header
        struct ether_header *eth_header = (struct ether_header*)_frame_buffer;
        memcpy(eth_header->ether_dhost, &l2_dest_addr, ETH_ALEN);
        memcpy(eth_header->ether_shost, &_mac_addr, ETH_ALEN);
        
        // Status of 0 means IP packet goes through
        // Statys of 1 means ARP packet
        if (status == NO_ERROR)
        {
            eth_header->ether_type = htons(ETHERTYPE_IP);
        }
        else
        {
            eth_header->ether_type = htons(ETHERTYPE_ARP);
        }
        
        // Calculate and populate CRC
        //_calcCRC(_frame_buffer, (size_t)(ETHER_HDR_LEN + len), _frame_buffer + ETHER_HDR_LEN + len);
        
        // If ARP hit, payload is IP packet
        // If ARP miss, payload is ARP request
        int bytes_written = pcap_inject(_handle, _frame_buffer, ETHER_HDR_LEN + len);// + ETHER_CRC_LEN);
        
        if (bytes_written <= 0)
        {
            status = INTERFACE_SEND_FAILED;
			Logger::Log(LOG_WARNING, "PCAP Inject Failed");
			Logger::Log(LOG_WARNING, pcap_geterr(_handle));
			Logger::Log(LOG_WARNING, std::to_string(ETHER_HDR_LEN + len));
        }
        else
        {
            status = NO_ERROR;
        }
    }

    return status;
}

void EthernetInterface::_captureLoop()
{
    pcap_loop(
        _handle,                        // Handle to interface
        0,                              // Max packets to capture
        &EthernetInterface::_receive,   // Callback
        (u_char*)this);                 // This object
}

///////////////////////////////////
//////// Private Functions ////////
///////////////////////////////////

void EthernetInterface::_receive(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	if (user == nullptr)
	{
		Logger::Log(LOG_DEBUG, "EthernetInterface::_receive got NULL user pointer.");
		return;
	}

	if (h->len > BUFSIZ)
	{
		Logger::Log(LOG_DEBUG, "Packet too large. Discarding");
		return;
	}

    // Cast user variable to pointer to ethernet interface object
    EthernetInterface *_this = (EthernetInterface*)user;
    
	std::stringstream sstream;
	sstream << "Received " << h->len << " bytes on " << _this->GetName();
	Logger::Log(LOG_DEBUG, sstream.str());

    // Pass to appropriate handler based on EtherType field
    struct ether_header *eth_header = (struct ether_header*)bytes;
    switch (ntohs(eth_header->ether_type))
    {
        case ETHERTYPE_ARP:
        {
            _this->_handle_arp(h, bytes);
            break;
        }
        case ETHERTYPE_IP:
        {
            _this->_handle_ip(h, bytes);
            break;
        }
        default:
        {
            // Other types not supported. Discard.
            break;
        }
    }
}

void EthernetInterface::_handle_ip(const struct pcap_pkthdr *h, const u_char *bytes)
{
    // Extract Layer 3 packet
    const uint8_t *l3_pkt;
    size_t l3_pkt_len;
    
    // Offset by size of ethernet header
    l3_pkt = bytes + ETHER_HDR_LEN;
    
    // Get size of L3 packet
    // Size of ethernet frame minus size of
    // header. Trailer is not included.
    l3_pkt_len = h->len - (ETHER_HDR_LEN);

    // If destination MAC is broadcast address, the packet
    // must not be routed. Drop now.
    struct ether_header *eth_header = (struct ether_header*)bytes;
    if (memcmp(&BROADCAST_MAC, eth_header->ether_dhost, ETH_ALEN) != 0)
    {
		// Execute callback
		_callback((ILayer2Interface*)this, l3_pkt, l3_pkt_len);
    }
    else
    {
    	Logger::Log(LOG_DEBUG, "Not routing broadcast frame");
    }
}

void EthernetInterface::_handle_arp(const struct pcap_pkthdr *h, const u_char *bytes)
{
    size_t l3_pkt_len = h->len - ETHER_HDR_LEN;
    
    ARPMessage arp_msg;
    int status = arp_msg.Deserialize(bytes + ETHER_HDR_LEN, l3_pkt_len);
    
    if (status != 0)
    {
        // Error derializing packet
        return;
    }
    
    switch (arp_msg.GetMessageType())
    {
        case ARP_MSG_TYPE_REPLY:
        {
            _handle_arp_reply(arp_msg);
            break;
        }
        case ARP_MSG_TYPE_REQUEST:
        {
            _handle_arp_request(arp_msg);
            break;
        }
        default:
        {
            break;
        }
    }
}

void EthernetInterface::_handle_arp_reply(ARPMessage &arp_msg)
{
    // Get ethernet address
    struct ether_addr l2_addr;
    memcpy(&l2_addr, arp_msg.GetSenderHWAddress(), ETH_ALEN);
    
    switch (arp_msg.GetProtocolType())
    {
        case ARP_PROTO_TYPE_IPV4:
        {
            struct sockaddr_in l3_addr;
            l3_addr.sin_family = AF_INET;
            l3_addr.sin_port = 0;
            memcpy(&l3_addr.sin_addr, arp_msg.GetSenderProtoAddress(), 4);
            
            struct sockaddr &_l3_addr = reinterpret_cast<struct sockaddr&>(l3_addr);
            
            _arp_table->SetARPEntry(_l3_addr, l2_addr);
            _arp_listener(_l3_addr, l2_addr);
            
            break;
        }
        case ARP_PROTO_TYPE_IPV6:
        {
            struct sockaddr_in6 l3_addr;
            l3_addr.sin6_family = AF_INET6;
            l3_addr.sin6_port = 0;
            l3_addr.sin6_flowinfo = 0;
            memcpy(&l3_addr.sin6_addr, arp_msg.GetSenderProtoAddress(), 16);
            
            struct sockaddr &_l3_addr = reinterpret_cast<struct sockaddr&>(l3_addr);
            
            _arp_table->SetARPEntry(_l3_addr, l2_addr);
            _arp_listener(_l3_addr, l2_addr);
            
            break;
        }
    }
}

void EthernetInterface::_handle_arp_request(ARPMessage &arp_msg)
{
    bool owned = false;
    
    switch (arp_msg.GetProtocolType())
    {
        case ARP_PROTO_TYPE_IPV4:
        {
            if (arp_msg.GetProtoAddrLen() != 4)
            {
                // Address length incorrect for IPv4.
                // Request is malformed.
                break;
            }
            
            struct sockaddr_in l3_addr;
            l3_addr.sin_family = AF_INET;
            l3_addr.sin_port = 0;
            memcpy(&l3_addr.sin_addr, arp_msg.GetTargetProtoAddress(), 4);
            
            struct sockaddr &_l3_addr = reinterpret_cast<struct sockaddr&>(l3_addr);
            
            owned = _owns_address((ILayer2Interface*)this, _l3_addr);
            
            break;
        }
        case ARP_PROTO_TYPE_IPV6:
        {
            if (arp_msg.GetProtoAddrLen() != 16)
            {
                // Address length incorrect for IPv6.
                // Request is malformed
                break;
            }
        
            struct sockaddr_in6 l3_addr;
            l3_addr.sin6_family = AF_INET6;
            l3_addr.sin6_port = 0;
            l3_addr.sin6_flowinfo = 0;
            memcpy(&l3_addr.sin6_addr, arp_msg.GetTargetProtoAddress(), 16);
            
            struct sockaddr &_l3_addr = reinterpret_cast<struct sockaddr&>(l3_addr);
            
            owned = _owns_address((ILayer2Interface*)this, _l3_addr);
        
            break;
        }
    }
    
    // If request was well-formed and address is
    // owned by this interface, send reply
    if (owned)
    {
        ARPMessage reply;
        _build_arp_reply(arp_msg, reply);
        
        struct ether_addr l2_dest_addr;
        memcpy(&l2_dest_addr, reply.GetTargetHWAddress(), ETH_ALEN);
        
        // Lock outgoing frame buffer
        std::scoped_lock {_mutex};
        
        size_t len = MAX_FRAME_LEN;
        int status = reply.Serialize(_frame_buffer + ETHER_HDR_LEN, len);
        
        if (status == 0)
        {
            struct ether_header *eth_header = (struct ether_header*)_frame_buffer;
            memcpy(eth_header->ether_dhost, &l2_dest_addr, ETH_ALEN);
            memcpy(eth_header->ether_shost, &_mac_addr, ETH_ALEN);
            eth_header->ether_type = htons(ETHERTYPE_ARP);
            
            pcap_inject(_handle, _frame_buffer, ETHER_HDR_LEN + len);
        }
    }
}

const char *EthernetInterface::GetName()
{
    return _if_name.c_str();
}

void EthernetInterface::_calcCRC(uint8_t *data, size_t len, uint8_t *crc)
{
    static const uint32_t poly = 0xEDB88320;
    uint32_t *_crc = (uint32_t*)crc;
    
    *_crc = 0xFFFFFFFF;
    
    int i, j;
    for (i = 0; i < len; i++)
    {
        char ch = data[i];
        for (j = 0; j < 8; j++)
        {
            uint32_t b = (ch^*_crc) & 1;
            *_crc >>= 1;
            if (b)
            {
                *_crc = *_crc ^ poly;
            }
            ch >>= 1;
        }
    }
    
    // Invert CRC
    *_crc = ~*_crc;
    
    // Convert host to network byte order
    *_crc = htonl(*_crc);
}

void EthernetInterface::SetMACAddress(const struct ether_addr &mac_addr)
{
    memcpy(&_mac_addr, &mac_addr, ETH_ALEN);
}

void EthernetInterface::SetIPAddressQueryMethod(IPOwnershipQuery method)
{
    _owns_address = method;
}

void EthernetInterface::_build_arp_reply(ARPMessage &request, ARPMessage &reply)
{
    // Set message type to reply
    reply.SetMessageType(ARP_MSG_TYPE_REPLY);
    
    // Get address lengths from request
    uint8_t hw_addr_len = request.GetHWAddrLen();
    uint8_t proto_addr_len = request.GetProtoAddrLen();
    
    // Fill out HW/Protocol information from request
    reply.SetHWType(request.GetHWType());
    reply.SetProtocolType(request.GetProtocolType());
    reply.SetHWAddrLen(hw_addr_len);
    reply.SetProtoAddrLen(proto_addr_len);
    
    // Swap sender/target addresses
    reply.SetTargetHWAddress(request.GetSenderHWAddress(), hw_addr_len);
    reply.SetTargetProtoAddress(request.GetSenderProtoAddress(), proto_addr_len);
    reply.SetSenderProtoAddress(request.GetTargetProtoAddress(), proto_addr_len);
    
    // Fill in MAC address
    reply.SetSenderHWAddress((uint8_t*)&_mac_addr, hw_addr_len);
}

void EthernetInterface::SetAsDefault()
{
	_is_default = true;
}
