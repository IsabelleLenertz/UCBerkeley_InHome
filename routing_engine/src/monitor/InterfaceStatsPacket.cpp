#include "monitor/InterfaceStatsPacket.hpp"
#include "status/error_codes.hpp"
#include <cstring>
#include <arpa/inet.h>

InterfaceStatsPacket::InterfaceStatsPacket()
	: _entries()
{
}

InterfaceStatsPacket::~InterfaceStatsPacket()
{
}

int InterfaceStatsPacket::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;
	uint32_t tmp;

	// Verify enough space for packet type
	if (len < sizeof(uint32_t))
	{
		return MONITOR_ERROR_OVERFLOW;
	}

	// Write packet type
	tmp = MONITOR_PACKET_TYPE_STATS;
	*((uint32_t*)(buff + offset)) = htonl(tmp);
	offset += sizeof(uint32_t);

	// Write interface entries
	for (auto e = _entries.begin(); e < _entries.end(); e++)
	{
		interface_stats_entry_t &entry = *e;

		// Calculate length needed to store interface name string
		size_t str_len = entry.if_name.size() + 1; // c-string length, including null character
		str_len = (((str_len - 1) / sizeof(uint32_t)) + 1) * sizeof(uint32_t); // Round up to 32-bit boundary

		// Verify enough space
		if (len < offset + str_len + sizeof(interface_stats_t))
		{
			return MONITOR_ERROR_OVERFLOW;
		}

		// Clear space for interface string
		memset(buff + offset, 0, str_len);
		// Copy data for interface string
		strcpy((char *)(buff + offset), entry.if_name.c_str());
		offset += str_len;

		// Copy fixed-size data portion
		uint32_t *ptr = (uint32_t*)&entry.data;
		for (size_t bytes_copied = 0; bytes_copied < sizeof(interface_stats_t); bytes_copied += sizeof(uint32_t))
		{
			// Byte swap and write each word
			tmp = ntohl(*ptr);
			*((uint32_t*)(buff + offset)) = tmp;
			ptr++;
			offset += sizeof(uint32_t);
		}
	}

	// Write length output
	len = offset;

	return NO_ERROR;
}

int InterfaceStatsPacket::Deserialize(const uint8_t *buff, size_t len)
{
	size_t offset = 0;
	uint32_t tmp;

	// Verify enough space for packet type
	if (len < sizeof(uint32_t))
	{
		return MONITOR_ERROR_OVERFLOW;
	}

	// Skip packet type (implied)
	offset += sizeof(uint32_t);

	while (offset < len)
	{
		// Get length of null-terminated string
		size_t str_len = strnlen((const char *)(buff + offset), len - offset);

		// Add null-terminator to length
		// If null-terminator was not found, this will push the
		// length over the total packet length and result in an error
		str_len++;

		// Round up to 32-bit boundary
		str_len = (((str_len - 1) / sizeof(uint32_t)) + 1) * sizeof(uint32_t);

		// Verify enough space for full entry
		if (len < offset + str_len + sizeof(interface_stats_t))
		{
			return MONITOR_ERROR_OVERFLOW;
		}

		// Create new entry
		_entries.emplace_back();
		interface_stats_entry_t &entry = _entries.back();

		// Read interface name string
		// String is guaranteed null-terminated
		entry.if_name = std::string((const char*)(buff + offset));
		offset += str_len;

		// Read fixed-length data portion
		uint32_t *ptr = (uint32_t*)&entry.data;
		for (size_t bytes_copied = 0; bytes_copied < sizeof(interface_stats_t); bytes_copied += sizeof(uint32_t))
		{
			// Byte swap and write each word
			tmp = *((uint32_t*)(buff + offset));
			*ptr = ntohl(tmp);
			ptr++;
			offset += sizeof(uint32_t);
		}
	}

	return NO_ERROR;
}

int InterfaceStatsPacket::GetPacketType()
{
	return MONITOR_PACKET_TYPE_STATS;
}

int InterfaceStatsPacket::GetInterfaceData(const char *name, interface_stats_t &data)
{
	bool found = false;

	// Search for an entry to overwrite
	for (auto e = _entries.begin(); e < _entries.end(); e++)
	{
		interface_stats_entry_t &entry = *e;
		if (strcmp(name, entry.if_name.c_str()) == 0)
		{
			memcpy(&data, &entry.data, sizeof(interface_stats_t));
			found = true;
			break;
		}
	}

	if (!found)
	{
		return MONITOR_ERROR_ENTRY_NOT_FOUND;
	}

	return NO_ERROR;
}

int InterfaceStatsPacket::SetInterfaceData(const char *name, interface_stats_t &data)
{
	bool found = false;

	// Search for an entry to overwrite
	for (auto e = _entries.begin(); e < _entries.end(); e++)
	{
		interface_stats_entry_t &entry = *e;
		if (strcmp(name, entry.if_name.c_str()) == 0)
		{
			memcpy(&entry.data, &data, sizeof(interface_stats_t));
			found = true;
			break;
		}
	}

	// If no entry was found, add a new one
	if (!found)
	{
		_entries.emplace_back();
		interface_stats_entry_t &new_entry = _entries.back();

		new_entry.if_name = std::string(name);
		memcpy(&new_entry.data, &data, sizeof(interface_stats_t));
	}

	return NO_ERROR;
}

size_t InterfaceStatsPacket::GetDataCount()
{
	return _entries.size();
}

int InterfaceStatsPacket::GetDataAt(size_t index, interface_stats_entry_t &data)
{
	// Check for index out of bounds
	if (index > _entries.size() - 1)
	{
		return MONITOR_ERROR_ENTRY_NOT_FOUND;
	}

	// Copy data
	data.if_name = _entries[index].if_name;
	memcpy(&data.data, &_entries[index].data, sizeof(interface_stats_t));

	return NO_ERROR;
}
