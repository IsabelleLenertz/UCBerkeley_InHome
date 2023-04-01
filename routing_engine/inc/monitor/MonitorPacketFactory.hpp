#ifndef INC_MONITORPACKETFACTORY_HPP_
#define INC_MONITORPACKETFACTORY_HPP_

#include "monitor/MonitorPacketBase.hpp"

class MonitorPacketFactory
{
public:
	static MonitorPacketBase* BuildPacket(const uint8_t *buff, size_t len);
};

#endif
