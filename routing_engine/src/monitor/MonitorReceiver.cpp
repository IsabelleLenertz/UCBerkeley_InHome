#include "monitor/MonitorReceiver.hpp"
#include "monitor/MonitorPacketFactory.hpp"
#include "status/error_codes.hpp"

#include <cstring>
#include <functional>
#include <iostream>
#include <iomanip>

MonitorReceiver::MonitorReceiver()
	: _socket_d(0),
	  _addr(),
	  _exiting(false),
	  _update_num(0)
{
	memset(_rcv_buff, 0, RCV_BUFF_SIZE);
}

MonitorReceiver::~MonitorReceiver()
{
}

int MonitorReceiver::Initialize(uint16_t port)
{
	_socket_d = socket(AF_INET, SOCK_DGRAM, 0);

	if (_socket_d < 0)
	{
		return MONITOR_ERROR_SOCKET_FAILED;
	}

	_addr.sin_family = AF_INET;
	_addr.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &_addr.sin_addr);

	int status = bind(_socket_d, reinterpret_cast<const struct sockaddr*>(&_addr), sizeof(struct sockaddr_in));

	if (status != 0)
	{
		return MONITOR_ERROR_BIND_FAILED;
	}

	// Start receive thread
	_th = std::thread(std::bind(&MonitorReceiver::_receive_loop, this));

	return NO_ERROR;
}

void MonitorReceiver::_receive_loop()
{
	while (!_exiting)
	{
		ssize_t bytes_received = recv(_socket_d, _rcv_buff, RCV_BUFF_SIZE, 0);

		if (bytes_received > 0)
		{
			// TODO Deserialize message
			if (bytes_received > sizeof(int))
			{
				MonitorPacketBase *pkt = MonitorPacketFactory::BuildPacket(_rcv_buff, bytes_received);

				if (pkt != nullptr)
				{
					int status = pkt->Deserialize(_rcv_buff, bytes_received);

					if (status == NO_ERROR)
					{
						_handle_packet(pkt);
					}

					delete pkt;
				}
			}
		}
	}
}

int MonitorReceiver::Close()
{
	if (_th.joinable())
	{
		_th.join();
	}

	return NO_ERROR;
}

int MonitorReceiver::_handle_packet(MonitorPacketBase* pkt)
{
	if (pkt == nullptr)
	{
		return MONITOR_ERROR_NULL_POINTER;
	}

	switch (pkt->GetPacketType())
	{
		case MONITOR_PACKET_TYPE_STATS:
		{
			return _handle_stats(reinterpret_cast<InterfaceStatsPacket*>(pkt));
		}
		default:
		{
			return MONITOR_ERROR_BAD_PACKET_TYPE;
		}
	}
}

int MonitorReceiver::_handle_stats(InterfaceStatsPacket* pkt)
{
	system("clear");
	_update_num++;
	std::cout << "---------------- Update Number: " << std::setw(6) << _update_num << " ----------------" << std::endl;
	std::cout << "Interface\tRX\tTX\tLocal Drops\tICMP RX\tICMP TX\tTCP RX\tTCP TX\tUDP RX\tUDP TX\tIPSEC RX\tIPSEC TX" << std::endl;

	size_t num_entries = pkt->GetDataCount();
	for (size_t i = 0; i < num_entries; i++)
	{
		interface_stats_entry_t entry;
		pkt->GetDataAt(i, entry);

		std::cout << entry.if_name << "\t\t" << entry.data.rx_count << "\t" << entry.data.tx_count << "\t" << entry.data.local_drop_count <<
				"\t\t" << entry.data.icmp_rx_count << "\t" << entry.data.icmp_tx_count << "\t" << entry.data.tcp_rx_count <<
				"\t" << entry.data.tcp_tx_count << "\t" << entry.data.udp_rx_count << "\t" << entry.data.udp_rx_count <<
				"\t" << entry.data.icmp_rx_count << "\t" << entry.data.icmp_tx_count << std::endl;
	}
}
