#include "layer4/ICMP/ICMPMessage.hpp"

#include "status/error_codes.hpp"
#include "layer3/IPUtils.hpp"

#include <arpa/inet.h>
#include <cstring>

#include <iostream>
#include <iomanip>

ICMPMessage::ICMPMessage()
	: _id(0),
	  _type(0),
	  _seq_num(0),
	  _data()
{
}

ICMPMessage::~ICMPMessage()
{
}

int ICMPMessage::Serialize(uint8_t *buff, size_t &len)
{
	uint8_t *ptr = buff;
	uint16_t tmp16;

	if (len < MIN_LEN_BYTES)
	{
		return ICMP_ERROR_OVERFLOW;
	}

	// Write type
	*ptr++ = _type;

	// Write code
	*ptr++ = 0;

	// Zero out checksum
	*(uint16_t*)ptr = 0;
	ptr += sizeof(uint16_t);

	// Write ID
	tmp16 = htons(_id);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write sequence number
	tmp16 = htons(_seq_num);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	if (len < MIN_LEN_BYTES + _data.size())
	{
		return ICMP_ERROR_OVERFLOW;
	}

	// Write data
	memcpy(ptr, _data.data(), _data.size());

	// Set length output
	len = MIN_LEN_BYTES + _data.size();

	// Write checksum
	tmp16 = IPUtils::Calc16BitChecksum(buff, len);
	*(uint16_t*)(buff + 2) = tmp16;

	return NO_ERROR;
}

int ICMPMessage::Deserialize(const uint8_t *data, size_t len)
{
	const uint8_t *ptr = data;
	uint16_t tmp16;

	// Verify enough data for header
	if (len < MIN_LEN_BYTES)
	{
		return ICMP_ERROR_OVERFLOW;
	}

	// Validate checksum
	tmp16 = IPUtils::Calc16BitChecksum(data, len);
	if (tmp16 != 0)
	{
		std::cout << std::hex << tmp16 << std::endl;
		return ICMP_ERROR_INVALID_CHECKSUM;
	}

	// Read type
	_type = *ptr;

	// Skip code and checksum
	ptr += sizeof(uint32_t);

	// Read ID
	tmp16 = *(uint16_t*)ptr;
	_id = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Read Sequence Number
	tmp16 = *(uint16_t*)ptr;
	_seq_num = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Read Data
	size_t num_data_bytes = len - MIN_LEN_BYTES;
	if (num_data_bytes > 0)
	{
		_data = std::vector<uint8_t>(ptr, ptr + num_data_bytes);
	}
	else
	{
		_data = std::vector<uint8_t>();
	}

	return NO_ERROR;
}

uint8_t ICMPMessage::GetType()
{
	return _type;
}

void ICMPMessage::SetType(uint8_t type)
{
	_type = type;
}

uint8_t ICMPMessage::GetCode()
{
	return 0;
}

uint16_t ICMPMessage::GetID()
{
	return _id;
}

void ICMPMessage::SetID(uint16_t id)
{
	_id = id;
}

uint16_t ICMPMessage::GetSequenceNumber()
{
	return _seq_num;
}

void ICMPMessage::SetSequenceNumber(uint16_t num)
{
	_seq_num = num;
}

const uint8_t *ICMPMessage::GetData()
{
	return _data.data();
}

size_t ICMPMessage::GetDataLength()
{
	return _data.size();
}

void ICMPMessage::SetData(const uint8_t *data, size_t len)
{
	_data = std::vector<uint8_t>(data, data + len);
}
