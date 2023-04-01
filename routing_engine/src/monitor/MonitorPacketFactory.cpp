#include "monitor/MonitorPacketFactory.hpp"
#include "monitor/InterfaceStatsPacket.hpp"
#include <arpa/inet.h>

MonitorPacketBase* MonitorPacketFactory::BuildPacket(const uint8_t *buff, size_t len)
{
	if (len < sizeof(int))
	{
		return nullptr;
	}

	int type = ntohl(*((uint32_t*)buff));

	switch (type)
	{
		case MONITOR_PACKET_TYPE_STATS:
		{
			return new InterfaceStatsPacket();
		}
		default:
		{
			return nullptr;
		}
	}
}
