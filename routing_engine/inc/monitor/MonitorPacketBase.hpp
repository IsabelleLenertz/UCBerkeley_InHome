#ifndef INC_MONITORPACKETBASE_HPP_
#define INC_MONITORPACKETBASE_HPP_

#include <cstdint>
#include <cstdlib>

#define MONITOR_PACKET_TYPE_RESERVED 0
#define MONITOR_PACKET_TYPE_STATS 1

class MonitorPacketBase
{
public:
	virtual ~MonitorPacketBase(){};

	virtual int Serialize(uint8_t *buff, size_t &len) = 0;
	virtual int Deserialize(const uint8_t *buff, size_t len) = 0;

	virtual int GetPacketType() = 0;
};



#endif
