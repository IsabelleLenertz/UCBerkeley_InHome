#include "layer4/TCPSegment.hpp"

#include <arpa/inet.h>
#include <cstring>

#include "status/error_codes.hpp"

TCPSegment::TCPSegment()
	: _src_port(0),
	  _dst_port(0),
	  _seq_num(0),
	  _ack_num(0),
	  _urg(false),
	  _ack(false),
	  _psh(false),
	  _rst(false),
	  _syn(false),
	  _fin(false),
	  _window(0),
	  _urgent_ptr(0),
	  _opts(),
	  _data()
{
}

TCPSegment::~TCPSegment()
{
}

int TCPSegment::Serialize(uint8_t *buff, size_t &len)
{
	uint8_t *ptr = buff;
	uint32_t tmp;
	uint16_t tmp16;

	// Ensure there are enough bytes for header
	if (len < MIN_HEADER_LEN_BYTES)
	{
		return TCP_ERROR_OVERFLOW;
	}

	// Write source port
	tmp16 = htons(_src_port);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write destination port
	tmp16 = htons(_dst_port);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write sequence number
	tmp = htonl(_seq_num);
	*(uint32_t*)ptr = tmp;
	ptr += sizeof(uint32_t);

	// Write ACK number
	tmp = htonl(_ack_num);
	*(uint32_t*)ptr = tmp;
	ptr += sizeof(uint32_t);

	// Write header length and flags
	int hdr_len_bytes = MIN_HEADER_LEN_BYTES + _opts.size();
	if (_opts.size() > 40)
	{
		return TCP_ERROR_OVERFLOW;
	}
	tmp16 = hdr_len_bytes / sizeof(uint32_t);
	tmp16 |= (_urg) ? 0x0400 : 0;
	tmp16 |= (_ack) ? 0x0800 : 0;
	tmp16 |= (_psh) ? 0x1000 : 0;
	tmp16 |= (_rst) ? 0x2000 : 0;
	tmp16 |= (_syn) ? 0x4000 : 0;
	tmp16 |= (_fin) ? 0x8000 : 0;
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Write Window Size
	tmp16 = htons(_window);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Zero-out checksum
	*(uint16_t*)ptr = 0;
	ptr += sizeof(uint16_t);

	// Write urgent pointer
	tmp16 = htons(_urgent_ptr);
	*(uint16_t*)ptr = tmp16;
	ptr += sizeof(uint16_t);

	// Ensure enough room for options
	if (len < hdr_len_bytes)
	{
		return TCP_ERROR_OVERFLOW;
	}

	// Write options
	memcpy(ptr, _opts.data(), _opts.size());
	ptr += _opts.size();

	// Ensure enough room for data
	if (len < hdr_len_bytes + _data.size())
	{
		return TCP_ERROR_OVERFLOW;
	}

	memcpy(ptr, _data.data(), _data.size());

	// Set output length, in bytes
	len = hdr_len_bytes + _data.size();

	return NO_ERROR;
}

int TCPSegment::Deserialize(const uint8_t *data, size_t len)
{
	const uint8_t *ptr = data;
	uint32_t tmp;
	uint16_t tmp16;

	// Ensure there are enough bytes for header
	if (len < MIN_HEADER_LEN_BYTES)
	{
		return TCP_ERROR_OVERFLOW;
	}

	// Read source port
	tmp16 = *(uint16_t*)ptr;
	_src_port = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Read destination port
	tmp16 = *(uint16_t*)ptr;
	_dst_port = ntohs(tmp16);

	ptr += sizeof(uint16_t);

	// Read sequence number
	tmp = *(uint32_t*)ptr;
	_seq_num = ntohl(tmp);
	ptr += sizeof(uint32_t);

	// Read ACK number
	tmp = *(uint32_t*)ptr;
	_ack_num = ntohl(tmp);
	ptr += sizeof(uint32_t);

	// Read header length and flags
	tmp16 = *(uint16_t*)ptr;
	size_t hdr_len_bytes = (tmp16 & 0xF) * sizeof(uint32_t);
	_urg = (tmp16 & 0x0400) != 0;
	_ack = (tmp16 & 0x0800) != 0;
	_psh = (tmp16 & 0x1000) != 0;
	_rst = (tmp16 & 0x2000) != 0;
	_syn = (tmp16 & 0x4000) != 0;
	_fin = (tmp16 & 0x8000) != 0;
	ptr += sizeof(uint16_t);

	// Read window size
	tmp16 = *(uint16_t*)ptr;
	_window = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Skip Checksum
	// In order to validate the checksum,
	// the IP pseudo-header is required
	// Caller will be responsible for this
	// validation
	ptr += sizeof(uint16_t);

	// Read urgent pointer
	tmp16 = *(uint16_t*)ptr;
	_urgent_ptr = ntohs(tmp16);
	ptr += sizeof(uint16_t);

	// Ensure enough data exists for options
	if (len < hdr_len_bytes)
	{
		return TCP_ERROR_OVERFLOW;
	}

	int num_opt_bytes = hdr_len_bytes - MIN_HEADER_LEN_BYTES;
	if (num_opt_bytes > 0)
	{
		_opts = std::vector<uint8_t>(ptr, ptr + num_opt_bytes);
	}
	else
	{
		_opts = std::vector<uint8_t>();
	}
	ptr += num_opt_bytes;

	int num_data_bytes = len - hdr_len_bytes;
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

uint16_t TCPSegment::GetSourcePort()
{
	return _src_port;
}

void TCPSegment::SetSourcePort(uint16_t port)
{
	_src_port = port;
}

uint16_t TCPSegment::GetDestinationPort()
{
	return _dst_port;
}

void TCPSegment::SetDestinationPort(uint16_t port)
{
	_dst_port = port;
}

uint32_t TCPSegment::GetSequenceNumber()
{
	return _seq_num;
}

void TCPSegment::SetSequenceNumber(uint32_t num)
{
	_seq_num = num;
}

uint32_t TCPSegment::GetAckNumber()
{
	return _ack_num;
}

void TCPSegment::SetAckNumber(uint32_t num)
{
	_ack_num = num;
}

size_t TCPSegment::GetHeaderLengthBytes()
{
	return MIN_HEADER_LEN_BYTES + _opts.size();
}

bool TCPSegment::GetURG()
{
	return _urg;
}

void TCPSegment::SetURG(bool urg)
{
	_urg = urg;
}

bool TCPSegment::GetACK()
{
	return _ack;
}

void TCPSegment::SetACK(bool ack)
{
	_ack = ack;
}

bool TCPSegment::GetPSH()
{
	return _psh;
}

void TCPSegment::SetPSH(bool psh)
{
	_psh = psh;
}

bool TCPSegment::GetRST()
{
	return _rst;
}

void TCPSegment::SetRST(bool rst)
{
	_rst = rst;
}

bool TCPSegment::GetSYN()
{
	return _syn;
}

void TCPSegment::SetSYN(bool syn)
{
	_syn = syn;
}

bool TCPSegment::GetFIN()
{
	return _fin;
}

void TCPSegment::SetFIN(bool fin)
{
	_fin = fin;
}

uint16_t TCPSegment::GetWindow()
{
	return _window;
}

void TCPSegment::SetWindow(uint16_t window)
{
	_window = window;
}

uint16_t TCPSegment::GetUrgentPtr()
{
	return _urgent_ptr;
}

void TCPSegment::SetUrgentPtr(uint16_t ptr)
{
	_urgent_ptr = ptr;
}

const uint8_t *TCPSegment::GetData()
{
	return _data.data();
}

size_t TCPSegment::GetDataLength()
{
	return _data.size();
}

void TCPSegment::SetData(const uint8_t *data, size_t len)
{
	_data = std::vector<uint8_t>(data, data + len);
}
