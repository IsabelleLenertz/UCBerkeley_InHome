#include "layer3/Layer3Router.hpp"

Layer3Router::Layer3Router()
    : _if_manager(),
      _config(),
      _access_control(),
      _rcv_queue(),
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
    Layer2ReceiveCallback callback = std::bind(&Layer3Router::_receive_packet, this);
    
    // Listen asynchronously on all interfaces
    status = _if_manager.ListenAll(callback);
    
    if (status != 0)
    {
        std::cout << "Failed to listen on interfaces" << std::endl;
        return 3;
    }
    
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
    // Check for changes in configuration
    if (_config.LocalIsOutdated())
    {
        // Command Update
        _config.UpdateLocal();
    }
    
    // Check for data in receive queue
    if (!_rcv_queue::Empty())
    {
        // Get data from queue
        std::pair<uint8_t*,size_t> data = _rcv_queue::Dequeue();
        
        // Pass to packet processing
        _process_packet(data.first, data.second);
    }
}

void Layer3Router::_receive_packet(const uint8_t *data, size_t len)
{
    // Copy into storage buffer
    uint8_t *buff = new uint8_t[len];
    memcpy(buff, data, len);
    
    // Add to receive queue
    // Ownership of buff pointer transfers
    // to receive queue
    _rcv_queue::Enqueue(std::pair<uint8_t*,size_t>(buff, len)));
}

void Layer3Router::_process_packet(const uint8_t *data, size_t len)
{
    
    IPPacket packet;
    
    int status = packet.Deserialize(data, len);
    
    if (status == 0)
    {
        // Consult Access Control Module
        bool allowed = _access_control.IsAllowed(packet);
        
        if (allowed)
        {
            // Packet is allowed. Serialize and send
            size_t len = SEND_BUFFER_SIZE;
            status = packet.Serialize(_send_buff, len);
            
            if (status == 0)
            {
                status = _if_manager.SendPacket(_send_buff, len);
                
                if (status != 0)
                {
                    // TODO Do stuff with status
                    // Some non-zero status values may not indicate failure
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
        std::cout << "Failed to deserialize packet" << std::endl;
    }
    
    // End of packet lifetime, free memory
    delete data;
}