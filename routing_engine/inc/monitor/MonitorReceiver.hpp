#ifndef INC_MONITOR_MONITORRECEIVER_HPP_
#define INC_MONITOR_MONITORRECEIVER_HPP_

#include "monitor/InterfaceStatsPacket.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>

class MonitorReceiver
{
public:
	MonitorReceiver();
	~MonitorReceiver();

	int Initialize(uint16_t port);
	int Close();

	static const size_t RCV_BUFF_SIZE = 1024;

private:
	int _socket_d;
	struct sockaddr_in _addr;
	uint8_t _rcv_buff[RCV_BUFF_SIZE];
	std::thread _th;
	bool _exiting;
	int _update_num;

	void _receive_loop();
	int _handle_packet(MonitorPacketBase* pkt);
	int _handle_stats(InterfaceStatsPacket* pkt);
};

#endif
