#include "monitor/MonitorSender.hpp"
#include "status/error_codes.hpp"

#include <cstring>
#include <arpa/inet.h>

MonitorSender::MonitorSender()
	: _socket_d(0),
	  _dstaddr()
{
	memset(_send_buff, 0, SEND_BUFF_SIZE);
}

MonitorSender::~MonitorSender()
{
}

int MonitorSender::Initialize(uint16_t dst_port)
{
	_socket_d = socket(AF_INET, SOCK_DGRAM, 0);

	if (_socket_d < 0)
	{
		return MONITOR_ERROR_SOCKET_FAILED;
	}

	_dstaddr.sin_family = AF_INET;
	_dstaddr.sin_port = htons(dst_port);
	inet_pton(AF_INET, "127.0.0.1", &_dstaddr.sin_addr);

	return NO_ERROR;
}

int MonitorSender::SendPacket(MonitorPacketBase *msg)
{
	size_t len = SEND_BUFF_SIZE;
	int status = msg->Serialize(_send_buff, len);

	if (status != NO_ERROR)
	{
		return status;
	}

	int bytes_sent = sendto(_socket_d, _send_buff, len, 0, reinterpret_cast<const struct sockaddr*>(&_dstaddr), sizeof(struct sockaddr_in));

	if (bytes_sent <= 0)
	{
		return MONITOR_ERROR_SEND_FAILED;
	}

	return NO_ERROR;
}
