#ifndef INC_WIFIINTERFACE_HPP_
#define INC_WIFIINTERFACE_HPP_

#include "layer2/ILayer2Interface.hpp"
#include "arp/IARPTable.hpp"
#include <string>

/// <summary>
/// Concrete implementation of ILayer2Interface
/// for WiFi interfaces
/// </summary>
class WiFiInterface : public ILayer2Interface
{
public:
    WiFiInterface(const char *if_name, IARPTable* arp_table);
    ~WiFiInterface();
    
    int Open();
    int Close();
    
    int Listen(Layer2ReceiveCallback& callback, bool async);
    int StopListen();
    
    int SendPacket(const struct sockaddr &l3_src_addr, const struct sockaddr &l3_dest_addr, const uint8_t *data, size_t len);
    
    const char *GetName();

private:
    std::string _if_name;
    IARPTable* _arp_table;
};

#endif
