#ifndef INC_WIFIINTERFACE_HPP_
#define INC_WIFIINTERFACE_HPP_

#include "layer2/ILayer2Interface.hpp"

class WiFiInterface : public ILayer2Interface
{
public:
    WiFiInterface();
    ~WiFiInterface();
    
    int Open(const char *if_name);
    int Close();
    
    int Listen(Layer2ReceiveCallback& callback, bool async);
    int StopListen();
    
    int SendPacket(const in_addr_t &l3_src_addr, const in_addr_t &l3_dest_addr, const uint8_t *data, size_t len);
};

#endif