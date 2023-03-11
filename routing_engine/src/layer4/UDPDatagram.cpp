#include "layer4/UDPDatagram.hpp"

#include <arpa/inet.h>
#include <cstring>

#include "status/error_codes.hpp"

UDPDatagram::UDPDatagram()
	: _src_port(0),
	  _dst_port(0),
	  _data()
{
}

UDPDatagram::~UDPDatagram()
{
}

int UDPDatagram::Serialize(uint8_t *buff, size_t &len)
{
	uint8_t *ptr = buff;
	uint16_t tmp16;

	if (len < MIN_DATAGRAM_SIZE_BYTES)
	{
		return UDP_ERROR_OVERFLOW;
	}

	// Write source port
	tmp16 = htons(_src_port);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write destination port
	tmp16 = htons(_dst_port);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write length
	tmp16 = MIN_DATAGRAM_SIZE_BYTES + _data.size();
	*(uint16_t*)ptr = htons(tmp16);
	ptr += sizeof(uint16_t);

	// Zero out checksum
	*(uint16_t*)ptr = 0;
	ptr += sizeof(uint16_t);

	if (len < MIN_DATAGRAM_SIZE_BYTES + _data.size())
	{
		return UDP_ERROR_OVERFLOW;
	}

	// Copy payload
	memcpy(ptr, _data.data(), _data.size());

	// Set output length, in bytes
	len = MIN_DATAGRAM_SIZE_BYTES + _data.size();

	return NO_ERROR;
}

int UDPDatagram::Deserialize(const uint8_t *data, size_t len)
{
	const uint8_t *ptr = data;
	uint16_t tmp16;

	if (len < MIN_DATAGRAM_SIZE_BYTES)
	{
		return UDP_ERROR_OVERFLOW;
	}

	tmp16 = *(uint16_t*)ptr;
	_src_port = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	tmp16 = *(uint16_t*)ptr;
	_dst_port = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Skip length
	ptr += sizeof(uint16_t);

	// Skip checksum
	ptr += sizeof(uint16_t);

	// Get Data
	int num_data_bytes = len - MIN_DATAGRAM_SIZE_BYTES;
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

uint16_t UDPDatagram::GetSourcePort()
{
	return _src_port;
}

void UDPDatagram::SetSourcePort(uint16_t port)
{
	_src_port = port;
}

uint16_t UDPDatagram::GetDestinationPort()
{
	return _dst_port;
}

void UDPDatagram::SetDestinationPort(uint16_t port)
{
	_dst_port = port;
}

size_t UDPDatagram::GetLengthBytes()
{
	return MIN_DATAGRAM_SIZE_BYTES + _data.size();
}

const uint8_t *UDPDatagram::GetData()
{
	return _data.data();
}

size_t UDPDatagram::GetDataLength()
{
	return _data.size();
}

void UDPDatagram::SetData(const uint8_t *data, size_t len)
{
	_data = std::vector<uint8_t>(data, data + len);
}
