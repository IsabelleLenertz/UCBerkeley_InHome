#include "nat/NAPTTable.hpp"
#include <cstring>
#include <ctime>
#include <unistd.h>

#include <sstream>
#include <arpa/inet.h>

#include "status/error_codes.hpp"

#include "layer3/IPUtils.hpp"
#include "layer4/ICMP/ICMPMessage.hpp"
#include "layer4/UDPDatagram.hpp"
#include "layer4/TCPSegment.hpp"

#include "logging/Logger.hpp"

NAPTTable::NAPTTable()
	: _tcp_table(),
	  _udp_table(),
	  _icmp_table(),
	  _mutex()
{
}

NAPTTable::~NAPTTable()
{
	// Close any remaining sockets
	for (auto e = _icmp_table.begin(); e < _icmp_table.end(); e++)
	{
		const napt_entry_t &entry = *e;

		close(entry.socket_d);
	}
	for (auto e = _udp_table.begin(); e < _udp_table.end(); e++)
	{
		const napt_entry_t &entry = *e;

		close(entry.socket_d);
	}
	for (auto e = _tcp_table.begin(); e < _tcp_table.end(); e++)
	{
		const napt_entry_t &entry = *e;

		close(entry.socket_d);
	}
}

int NAPTTable::TranslateToInternal(IIPPacket *packet)
{
	int status = ERROR_UNSET;
	std::scoped_lock lock {_mutex};

	switch (packet->GetProtocol())
	{
		case IPPROTO_ICMP:
		{
			// Deserialize ICMP message from packet data
			ICMPMessage icmp;
			const uint8_t *data;
			size_t data_len = packet->GetData(data);

			status = icmp.Deserialize(data, data_len);

			if (status != NO_ERROR)
			{
				return status;
			}

			napt_tuple_t *mapped_addr = GetInternal(IPPROTO_ICMP, packet->GetDestinationAddress(), icmp.GetID());

			if (mapped_addr == nullptr)
			{
				return NAT_ERROR_MAPPING_NOT_FOUND;
			}

			// At this point, mapped_addr, is guaranteed to point to
			// a valid mapping. Apply the mapping.
			icmp.SetID(mapped_addr->identifier);
			packet->SetDestinationAddress(reinterpret_cast<const struct sockaddr&>(mapped_addr->addr));

			// Reserialize ICMP Message
			uint8_t buff[data_len];
			status = icmp.Serialize(buff, data_len);

			if (status != NO_ERROR)
			{
				return status;
			}

			// Copy data into packet
			packet->SetData(buff, data_len);

			break;
		}
		case IPPROTO_UDP:
		{
			break;
		}
		case IPPROTO_TCP:
		{
			// TCP NAPT disabled
			break;

			// Deserialize TCP data from packet data
			TCPSegment tcp;
			const uint8_t *data;
			size_t data_len = packet->GetData(data);

			status = tcp.Deserialize(data, data_len);

			if (status != NO_ERROR)
			{
				return status;
			}

			napt_tuple_t *mapped_addr = GetInternal(IPPROTO_TCP, packet->GetDestinationAddress(), tcp.GetDestinationPort());

			if (mapped_addr == nullptr)
			{
				Logger::Log(LOG_DEBUG, "Mapping not found. Dropping");
				return NAT_ERROR_MAPPING_NOT_FOUND;
			}

			// At this point, mapped_addr, is guaranteed to point to
			// a valid mapping. Apply the mapping.
			tcp.SetDestinationPort(mapped_addr->identifier);
			packet->SetDestinationAddress(reinterpret_cast<const struct sockaddr&>(mapped_addr->addr));

			// Reserialize TCP Message
			uint8_t buff[TCP_PSEUDO_HEADER_LEN + data_len];
			status = tcp.Serialize(buff + TCP_PSEUDO_HEADER_LEN, data_len);

			// Populate pseudo header
			const struct sockaddr_in &src_addr = reinterpret_cast<const struct sockaddr_in&>(packet->GetSourceAddress());
			const struct sockaddr_in &dst_addr = reinterpret_cast<const struct sockaddr_in&>(packet->GetDestinationAddress());
			memcpy(buff, &src_addr.sin_addr, 4);
			memcpy(buff + 4, &dst_addr.sin_addr, 4);
			*(uint8_t*)(buff + 9) = packet->GetProtocol();
			*(uint16_t*)(buff + 10) = htons(tcp.GetLengthBytes());

			// Calculate checksum
			uint16_t checksum = IPUtils::Calc16BitChecksum(buff, TCP_PSEUDO_HEADER_LEN + data_len);
			*(uint16_t*)(buff + 12 + 16) = htons(checksum);

			// Copy data into packet
			packet->SetData(buff + TCP_PSEUDO_HEADER_LEN, data_len);

			break;
		}
		default:
		{
			return NAT_ERROR_UNSUPPORTED_PROTOCOL;
		}
	}

	return NO_ERROR;
}

int NAPTTable::TranslateToExternal(IIPPacket *packet, const struct sockaddr &external_ip)
{
	std::stringstream sstream;
	int status = ERROR_UNSET;
	std::scoped_lock lock {_mutex};

	switch (packet->GetProtocol())
	{
		case IPPROTO_ICMP:
		{
			// Deserialize ICMP message from packet data
			ICMPMessage icmp;
			const uint8_t *data;
			size_t data_len = packet->GetData(data);

			status = icmp.Deserialize(data, data_len);

			if (status != NO_ERROR)
			{
				return status;
			}

			// Attempt to locate an existing mapping
			napt_tuple_t *mapped_addr = GetExternal(IPPROTO_ICMP, packet->GetSourceAddress(), icmp.GetID());

			if (mapped_addr == nullptr)
			{
				// Create a mapping
				mapped_addr = CreateMappingToExternal(IPPROTO_ICMP, packet->GetSourceAddress(), icmp.GetID(), external_ip);

				if (mapped_addr == nullptr)
				{
					return NAT_ERROR_CREATE_MAPPING_FAILED;
				}
			}
			// At this point, mapped_addr is guaranteed to point to
			// a valid mapping. Apply the mapping.
			icmp.SetID(mapped_addr->identifier);
			packet->SetSourceAddress(reinterpret_cast<struct sockaddr&>(mapped_addr->addr));

			// Reserialize ICMP message
			uint8_t buff[data_len];
			status = icmp.Serialize(buff, data_len);

			if (status != NO_ERROR)
			{
				return status;
			}

			// Copy data into packet
			packet->SetData(buff, data_len);

			break;
		}
		case IPPROTO_UDP:
		{
			break;
		}
		case IPPROTO_TCP:
		{
			// TCP NAPT disabled
			break;

			// Deserialize TCP message from packet data
			TCPSegment tcp;
			const uint8_t *data;
			size_t data_len = packet->GetData(data);

			status = tcp.Deserialize(data, data_len);

			if (status != NO_ERROR)
			{
				sstream.str("");
				sstream << "Failed to deserialize TCP segment: (" << status << ")";
				Logger::Log(LOG_DEBUG, sstream.str());
				return status;
			}

			// Attempt to locate an existing mapping
			napt_tuple_t *mapped_addr = GetExternal(IPPROTO_TCP, packet->GetSourceAddress(), tcp.GetSourcePort());

			if (mapped_addr == nullptr)
			{
				Logger::Log(LOG_DEBUG, "Mapping not found. Creating mapping.");

				// Create a mapping
				mapped_addr = CreateMappingToExternal(IPPROTO_TCP, packet->GetSourceAddress(), tcp.GetSourcePort(), external_ip);

				if (mapped_addr == nullptr)
				{
					Logger::Log(LOG_DEBUG, "Failed to create mapping.");
					return NAT_ERROR_CREATE_MAPPING_FAILED;
				}
			}

			// At this point, mapped_addr is guaranteed to point to
			// a valid mapping. Apply the mapping.
			tcp.SetSourcePort(mapped_addr->identifier);
			packet->SetSourceAddress(reinterpret_cast<struct sockaddr&>(mapped_addr->addr));

			// Reserialize TCP Message
			uint8_t buff[TCP_PSEUDO_HEADER_LEN + data_len];
			status = tcp.Serialize(buff + TCP_PSEUDO_HEADER_LEN, data_len);

			// Populate pseudo header
			const struct sockaddr_in &src_addr = reinterpret_cast<const struct sockaddr_in&>(packet->GetSourceAddress());
			const struct sockaddr_in &dst_addr = reinterpret_cast<const struct sockaddr_in&>(packet->GetDestinationAddress());
			memcpy(buff, &src_addr.sin_addr, 4);
			memcpy(buff + 4, &dst_addr.sin_addr, 4);
			*(uint8_t*)(buff + 9) = packet->GetProtocol();
			*(uint16_t*)(buff + 10) = htons(tcp.GetLengthBytes());

			// Calculate checksum
			uint16_t checksum = IPUtils::Calc16BitChecksum(buff, TCP_PSEUDO_HEADER_LEN + data_len);
			*(uint16_t*)(buff + 12 + 16) = htons(checksum);

			// Copy data into packet
			packet->SetData(buff + TCP_PSEUDO_HEADER_LEN, data_len);

			break;
		}
		default:
		{
			Logger::Log(LOG_DEBUG, "Unsupported protocol");
			return NAT_ERROR_UNSUPPORTED_PROTOCOL;
		}
	}

	return NO_ERROR;
}

napt_tuple_t *NAPTTable::GetInternal(uint8_t protocol, const struct sockaddr &ip_addr, uint16_t id)
{
	// This is a private method which is called only from the context of TranslateToInternal
	// DO NOT lock the mutex, as this will result in deadlock

	napt_tuple_t *result = nullptr;

	// Point to the correct translation table based
	// on the protocol requested
	std::vector<napt_entry_t> *table = nullptr;
	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			table = &_icmp_table;
			break;
		}
		case IPPROTO_UDP:
		{
			table = &_udp_table;
			break;
		}
		case IPPROTO_TCP:
		{
			table = &_tcp_table;
			break;
		}
		default:
		{
			break;
		}
	}

	if (table != nullptr)
	{
		// Search the table for an entry which matches the
		// specified address/identifier tuple
		for (auto e = table->begin(); e < table->end(); e++)
		{
			napt_entry_t &entry = *e;

			// If the ID and address match the external entry, return the corresponding internal entry
			if (id == entry.external.identifier && IPUtils::AddressesAreEqual(ip_addr, reinterpret_cast<const struct sockaddr&>(entry.external.addr)))
			{
				result = &entry.internal;

				// Refresh entry expiration time
				entry.expires_at = time(NULL) + NAPT_EXP_TIME_SEC;

				break;
			}
		}
	}

	return result;
}

napt_tuple_t *NAPTTable::GetExternal(uint8_t protocol, const struct sockaddr &ip_addr, uint16_t id)
{
	// This is a private method which is called only from the context of TranslateToExternal
	// DO NOT lock the mutex, as this will result in deadlock

	napt_tuple_t *result = nullptr;

	// Point to the correct translation table based
	// on the protocol requested
	std::vector<napt_entry_t> *table = nullptr;
	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			table = &_icmp_table;
			break;
		}
		case IPPROTO_UDP:
		{
			table = &_udp_table;
			break;
		}
		case IPPROTO_TCP:
		{
			table = &_tcp_table;
			break;
		}
		default:
		{
			break;
		}
	}

	if (table != nullptr)
	{
		// Search the table for an entry which matches theexternal_id
		// specified address/identifier tuple
		for (auto e = table->begin(); e < table->end(); e++)
		{
			napt_entry_t &entry = *e;

			// If the ID and address match the internal entry, return the corresponding external entry
			if (id == entry.internal.identifier && IPUtils::AddressesAreEqual(ip_addr, reinterpret_cast<const struct sockaddr&>(entry.internal.addr)))
			{
				result = &entry.external;

				// Refresh entry expiration time
				entry.expires_at = time(NULL) + NAPT_EXP_TIME_SEC;

				break;
			}
		}
	}

	return result;
}

napt_tuple_t *NAPTTable::CreateMappingToExternal(uint8_t protocol, const sockaddr &internal_ip, uint16_t id, const sockaddr &external_ip)
{
	// This is a private method which is called only from the context of TranslateToExternal
	// DO NOT lock the mutex, as this will result in deadlock
	napt_tuple_t *result = nullptr;

	int socket_d;
	uint16_t external_id;
	int status = BindMapping(protocol, external_ip, socket_d, external_id);

	if (status != NO_ERROR)
	{
		return nullptr;
	}

	// Select table based on protocol
	std::vector<napt_entry_t> *table = nullptr;
	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			table = &_icmp_table;
			break;
		}
		case IPPROTO_UDP:
		{
			table = &_udp_table;
			break;
		}
		case IPPROTO_TCP:
		{
			table = &_tcp_table;
			break;
		}
		default:
		{
			break;
		}
	}

	if (table == nullptr)
	{
		return nullptr;
	}

	// Add new entry and get a reference to it
	table->push_back(napt_entry_t {0});
	napt_entry_t &new_entry = table->back();

	// Populate entry
	IPUtils::StoreSockaddr(internal_ip, new_entry.internal.addr);
	new_entry.internal.identifier = id;
	IPUtils::StoreSockaddr(external_ip, new_entry.external.addr);
	new_entry.external.identifier = external_id;
	new_entry.socket_d = socket_d;

	// Set initial expiration time
	new_entry.expires_at = time(NULL) + NAPT_EXP_TIME_SEC;

	// Set the result to the external tuple of the new entry
	result = &new_entry.external;

	return result;
}

int NAPTTable::BindMapping(uint8_t protocol, const sockaddr &external_ip, int &socket_d, uint16_t &id)
{
	socket_d = -1;
	int status = ERROR_UNSET;

	char ipstr[64];
	const struct sockaddr_in &_external_ip = reinterpret_cast<const sockaddr_in&>(external_ip);
	inet_ntop(AF_INET, &_external_ip.sin_addr, ipstr, 64);

	// Based on the protocol, open a socket
	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			socket_d = socket(external_ip.sa_family, SOCK_DGRAM, IPPROTO_ICMP);
			break;
		}
		case IPPROTO_UDP:
		{
			socket_d = socket(external_ip.sa_family, SOCK_DGRAM, IPPROTO_UDP);
			break;
		}
		case IPPROTO_TCP:
		{
			socket_d = socket(external_ip.sa_family, SOCK_STREAM, IPPROTO_TCP);
			break;
		}
		default:
		{
			return NAT_ERROR_UNSUPPORTED_PROTOCOL;
		}
	}

	if (socket_d < 0)
	{
		return NAT_ERROR_SOCKET_CREATE_FAILED;
	}

	// Bind the socket and retrieve the identifier
	// (Query ID or Port, as applicable) bound to the socket
	switch (external_ip.sa_family)
	{
		case AF_INET:
		{
			// Bind the socket
			status = bind(socket_d, &external_ip, sizeof(struct sockaddr_in));
			if (status != NO_ERROR)
			{
				return NAT_ERROR_SOCKET_BIND_FAILED;
			}

			// Retrieve bound address
			struct sockaddr_in saddr;
			socklen_t addrlen;
			struct sockaddr &_saddr = reinterpret_cast<struct sockaddr&>(saddr);

			status = getsockname(socket_d, &_saddr, &addrlen);

			id = saddr.sin_port;

			break;
		}
		case AF_INET6:
		{
			// Bind the socket
			status = bind(socket_d, &external_ip, sizeof(struct sockaddr_in6));
			if (status != NO_ERROR)
			{
				return NAT_ERROR_SOCKET_BIND_FAILED;
			}

			// Retrieve bound address
			struct sockaddr_in6 saddr;
			socklen_t addrlen;
			struct sockaddr &_saddr = reinterpret_cast<struct sockaddr&>(saddr);

			status = getsockname(socket_d, &_saddr, &addrlen);

			id = saddr.sin6_port;

			break;
		}
		default:
		{
			return NAT_ERROR_UNSUPPORTED_PROTOCOL;
		}
	}

	if (status != NO_ERROR)
	{
		return NAT_ERROR_GET_ADDRESS_FAILED;
	}

	return NO_ERROR;
}

void NAPTTable::AddEntry(uint8_t protocol, const napt_entry_t &new_entry)
{
	char ip_str[64];

	const struct sockaddr &new_internal = reinterpret_cast<const struct sockaddr&>(new_entry.internal.addr);
	const struct sockaddr &new_external = reinterpret_cast<const struct sockaddr&>(new_entry.external.addr);
	const struct sockaddr_in &_new_internal = reinterpret_cast<const struct sockaddr_in&>(new_entry.internal.addr);
	const struct sockaddr_in &_new_external = reinterpret_cast<const struct sockaddr_in&>(new_entry.external.addr);

	std::vector<napt_entry_t> *table = nullptr;

	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			table = &_icmp_table;
			break;
		}
		case IPPROTO_UDP:
		{
			table = &_udp_table;
			break;
		}
		case IPPROTO_TCP:
		{
			table = &_tcp_table;
			break;
		}
	}

	for (auto e = table->begin(); e < table->end(); e++)
	{
		napt_entry_t entry = *e;
		const struct sockaddr &internal = reinterpret_cast<const struct sockaddr&>(entry.internal.addr);
		const struct sockaddr &external = reinterpret_cast<const struct sockaddr&>(entry.external.addr);

		// Check if the entry matches the external OR internal tuple
		const struct sockaddr_in &_internal = reinterpret_cast<const struct sockaddr_in&>(entry.internal.addr);
		const struct sockaddr_in &_external = reinterpret_cast<const struct sockaddr_in&>(entry.external.addr);

		if ((new_entry.external.identifier == entry.external.identifier &&
			 IPUtils::AddressesAreEqual(new_external, external)) ||
			(new_entry.internal.identifier == entry.internal.identifier &&
			 IPUtils::AddressesAreEqual(new_internal, internal)))
		{
			table->erase(e);
		}
	}

	if (table != nullptr)
	{
		table->push_back(new_entry);
	}
}

void NAPTTable::RemoveExpired()
{
	time_t current_time = time(NULL);

	for (auto e = _icmp_table.begin(); e < _icmp_table.end(); e++)
	{
		napt_entry_t &entry = *e;

		// If the expiration time is not 0 (special case: no expiration)
		// and is before the current time, close the socket
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			close(entry.socket_d);
			_icmp_table.erase(e);
		}
	}

	for (auto e = _udp_table.begin(); e < _udp_table.end(); e++)
	{
		napt_entry_t &entry = *e;

		// If the expiration time is not 0 (special case: no expiration)
		// and is before the current time, close the socket
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			close(entry.socket_d);
			_udp_table.erase(e);
		}
	}

	for (auto e = _tcp_table.begin(); e < _tcp_table.end(); e++)
	{
		napt_entry_t &entry = *e;

		// If the expiration time is not 0 (special case: no expiration)
		// and is before the current time, close the socket
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			close(entry.socket_d);
			_tcp_table.erase(e);
		}
	}
}
