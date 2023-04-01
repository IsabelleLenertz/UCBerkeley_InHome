#ifndef INC_INTERFACESTATSPACKET_HPP_
#define INC_INTERFACESTATSPACKET_HPP_

#include "monitor/MonitorPacketBase.hpp"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

typedef struct
{
	uint32_t rx_count;         // Number of packets received (any protocol)
	uint32_t tx_count;         // Number of packets transmitted (any protocol)
	uint32_t local_drop_count; // Number of packets dropped because destination was local
	uint32_t icmp_rx_count;    // Number of packets received (ICMP)
	uint32_t icmp_tx_count;    // Number of packets transmitted (ICMP)
	uint32_t tcp_rx_count;     // Number of packets received (TCP)
	uint32_t tcp_tx_count;     // Number of packets transmitted (TCP)
	uint32_t udp_rx_count;     // Number of packets received (UDP)
	uint32_t udp_tx_count;     // Number of packets transmitted (UDP)
	uint32_t ipsec_rx_count;   // Number of packets received (IPSEC)
	uint32_t ipsec_tx_count;   // Number of packets transmitted (IPSEC)
} interface_stats_t;

typedef struct
{
	std::string if_name;
	interface_stats_t data;
} interface_stats_entry_t;

class InterfaceStatsPacket : public MonitorPacketBase
{
public:
	InterfaceStatsPacket();
	~InterfaceStatsPacket() override;

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *buff, size_t len);

	int GetPacketType();

	int GetInterfaceData(const char *name, interface_stats_t &data);
	int SetInterfaceData(const char *name, interface_stats_t &data);

	size_t GetDataCount();
	int GetDataAt(size_t index, interface_stats_entry_t &data);

private:
	std::vector<interface_stats_entry_t> _entries;
};

#endif
