#ifndef INC_MONITORSENDER_HPP_
#define INC_MONITORSENDER_HPP_

#include "monitor/InterfaceStatsPacket.hpp"
#include "status/error_codes.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>

class MonitorSender
{
public:
	MonitorSender();
	~MonitorSender();

	int Initialize(uint16_t dst_port);
	int SendPacket(MonitorPacketBase *msg);

	static const size_t SEND_BUFF_SIZE = 1024;

private:
	int _socket_d;
	struct sockaddr_in _dstaddr;
	uint8_t _send_buff[SEND_BUFF_SIZE];
};

#endif
