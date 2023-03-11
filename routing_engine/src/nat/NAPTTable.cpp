#include "nat/NAPTTable.hpp"
#include <cstring>
#include <ctime>

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
	// Mark all TCP/UDP/ICMP IDs as available,
	// since no mappings exist yet
	memset(_tcp_portmap, 0, sizeof(_tcp_portmap));
	memset(_udp_portmap, 0, sizeof(_udp_portmap));
	memset(_icmp_idmap, 0, sizeof(_icmp_idmap));
}

NAPTTable::~NAPTTable()
{
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
			break;
		}
		default:
		{
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
		// Search the table for an entry which matches the
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

	// Reserve an ID number
	uint16_t external_id;
	int status = ReserveID(protocol, external_id);

	if (status != NO_ERROR)
	{
		return nullptr;
	}

	// Point to the correct translation table based on the protocol requested
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

	if (table != nullptr)
	{
		// Add new entry and get a reference to it
		table->push_back(napt_entry_t {0});
		napt_entry_t &new_entry = table->back();

		// Populate entry
		IPUtils::StoreSockaddr(internal_ip, new_entry.internal.addr);
		new_entry.internal.identifier = id;
		IPUtils::StoreSockaddr(external_ip, new_entry.external.addr);
		new_entry.external.identifier = external_id;

		Logger::Log(LOG_DEBUG, "Created mapping");

		// Set initial expiration time
		new_entry.expires_at = time(NULL) + NAPT_EXP_TIME_SEC;

		// Set the result to the external tuple of the new entry
		result = &new_entry.external;
	}

	return result;
}

int NAPTTable::ReserveID(uint8_t protocol, uint16_t &id)
{
	uint32_t *map = nullptr;
	size_t mapsize = 0;
	uint16_t min_id = 0;
	bool found = false;

	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			map = (uint32_t*)&_icmp_idmap;
			mapsize = sizeof(_icmp_idmap) / sizeof(uint32_t);
			min_id = ICMP_ID_START;
			break;
		}
		case IPPROTO_UDP:
		{
			map = (uint32_t*)&_udp_portmap;
			mapsize = sizeof(_udp_portmap) / sizeof(uint32_t);
			min_id = UDP_PORT_START;
			break;
		}
		case IPPROTO_TCP:
		{
			map = (uint32_t*)&_tcp_portmap;
			mapsize = sizeof(_tcp_portmap) / sizeof(uint32_t);
			min_id = TCP_PORT_START;
			break;
		}
		default:
		{
			break;
		}
	}

	if (map != nullptr)
	{
		int word_num  = 0;
		int bit_num = 0;

		for (word_num = 0; word_num < mapsize; word_num++)
		{
			// Check if all ports at this word are in use
			if (map[word_num] == 0xFFFFFFFF)
			{
				// All in use. Skip.
				continue;
			}

			uint32_t bitmask = 1;
			for (bit_num = 0; bit_num < 32; bit_num++)
			{
				if ((map[word_num] & bitmask) == 0)
				{
					// Found available port
					found = true;

					// Mark port as in-use
					map[word_num] |= bitmask;
					break;
				}
				bitmask <<= 1;
			}

			if (found)
			{
				break;
			}
		}

		if (!found)
		{
			return NAT_ERROR_NO_AVAILABLE_ID;
		}

		// Calculate port offset from word/bit number
		uint16_t offset = word_num * 32 + bit_num;
		id = min_id + offset;
	}
	else
	{
		return NAT_ERROR_UNSUPPORTED_PROTOCOL;
	}

	return NO_ERROR;
}

int NAPTTable::FreeID(uint8_t protocol, uint16_t id)
{
	uint32_t *map = nullptr;
	size_t mapsize = 0;
	uint16_t min_id = 0;

	switch (protocol)
	{
		case IPPROTO_ICMP:
		{
			if (id > ICMP_ID_END)
			{
				return NAT_ERROR_OUT_OF_RANGE;
			}

			map = (uint32_t*)&_icmp_idmap;
			mapsize = sizeof(_icmp_idmap) / sizeof(uint32_t);
			min_id = ICMP_ID_START;
			break;
		}
		case IPPROTO_UDP:
		{
			if (id > UDP_PORT_END)
			{
				return NAT_ERROR_OUT_OF_RANGE;
			}

			map = (uint32_t*)&_udp_portmap;
			mapsize = sizeof(_udp_portmap) / sizeof(uint32_t);
			min_id = UDP_PORT_START;
			break;
		}
		case IPPROTO_TCP:
		{
			if (id > TCP_PORT_END)
			{
				return NAT_ERROR_OUT_OF_RANGE;
			}

			map = (uint32_t*)&_tcp_portmap;
			mapsize = sizeof(_tcp_portmap) / sizeof(uint32_t);
			min_id = TCP_PORT_START;
			break;
		}
		default:
		{
			break;
		}
	}

	if (map != nullptr)
	{
		uint16_t offset = id - min_id;
		int word_num = offset / 32;
		int bit_num = offset % 32;
		uint32_t bitmask = ~(1 << bit_num);

		// Clear bit
		map[word_num] &= bitmask;

		return NO_ERROR;
	}
	else
	{
		return NAT_ERROR_UNSUPPORTED_PROTOCOL;
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
		// and is before the current time, free the external ID
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			FreeID(IPPROTO_ICMP, entry.external.identifier);
			_icmp_table.erase(e);
		}
	}

	for (auto e = _udp_table.begin(); e < _udp_table.end(); e++)
	{
		napt_entry_t &entry = *e;

		// If the expiration time is not 0 (special case: no expiration)
		// and is before the current time, free the external ID
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			FreeID(IPPROTO_UDP, entry.external.identifier);
			_udp_table.erase(e);
		}
	}

	for (auto e = _tcp_table.begin(); e < _tcp_table.end(); e++)
	{
		napt_entry_t &entry = *e;

		// If the expiration time is not 0 (special case: no expiration)
		// and is before the current time, free the external ID
		// and remove the entry from the list
		if (entry.expires_at != 0 && entry.expires_at < current_time)
		{
			FreeID(IPPROTO_TCP, entry.external.identifier);
			_tcp_table.erase(e);
		}
	}
}
