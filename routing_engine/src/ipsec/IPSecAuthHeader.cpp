#include "ipsec/IPSecAuthHeader.hpp"
#include <netinet/in.h>
#include "status/error_codes.hpp"
#include <arpa/inet.h>
#include <cstring>

#include <iostream>
#include "logging/Logger.hpp"

IPSecAuthHeader::IPSecAuthHeader()
	: _next_hdr(IPPROTO_TCP),
	  _payload_len(0),
	  _spi(0),
	  _seq_num(0),
	  _icv(0)
{
}

IPSecAuthHeader::~IPSecAuthHeader()
{
}

int IPSecAuthHeader::Serialize(uint8_t *buff, size_t &len)
{
	uint8_t *ptr = buff;
	uint32_t tmp;

	// Verify enough data for full header
	size_t hdr_len = GetLengthBytes();
	if (len < hdr_len)
	{
		return IPSEC_AH_ERROR_OVERFLOW;
	}

	// Clear memory to ensure zero-padding
	memset(buff, 0, hdr_len);

	// Write next header
	*ptr++ = _next_hdr;

	// Write payload length
	// Number of 32-bit words in header
	// minus the first 2
	*ptr++ = (uint8_t)((hdr_len / sizeof(uint32_t)) - 2);

	// Clear reserved bytes
	*(uint16_t*)ptr = 0;
	ptr += sizeof(uint16_t);

	// Write SPI
	tmp = ntohl(_spi);
	*(uint32_t*)ptr = tmp;
	ptr += sizeof(uint32_t);

	// Write sequence number
	tmp = ntohl(_seq_num);
	*(uint32_t*)ptr = tmp;
	ptr += sizeof(uint32_t);

	// Write ICV
	memcpy(ptr, _icv.data(), _icv.size());

	// Set output length
	len = hdr_len;

	return NO_ERROR;
}

int IPSecAuthHeader::Deserialize(const uint8_t *data, size_t &len)
{
	const uint8_t *ptr = data;
	uint32_t tmp;

	// Verify enough data for fixed bytes
	if (len < AH_MIN_LEN_BYTES)
	{
		return IPSEC_AH_ERROR_OVERFLOW;
	}

	// Get next header
	_next_hdr = *ptr++;

	// Ensure enough data for stated length
	// Total header length (in bytes) is the
	// payload length (in 32-bit words) plus 2,
	// multiplied by 4
	size_t hdr_len_bytes = (size_t)*ptr++;
	hdr_len_bytes = (hdr_len_bytes + 2) * sizeof(uint32_t);

	if (len < hdr_len_bytes)
	{
		return IPSEC_AH_ERROR_OVERFLOW;
	}

	// Skip reserved bytes
	ptr += sizeof(uint16_t);

	// Get SPI
	tmp = *(uint32_t*)ptr;
	_spi = ntohl(tmp);
	ptr += sizeof(uint32_t);

	// Get sequence number
	tmp = *(uint32_t*)ptr;
	_seq_num = ntohl(tmp);
	ptr += sizeof(uint32_t);

	// Get ICV length in bytes
	// Equal to the full length minus
	// the first 3 32-bit words
	size_t icv_len_bytes = hdr_len_bytes - (3 * sizeof(uint32_t));

	std::stringstream sstream;
	sstream << "ICV Length: " << icv_len_bytes;
	Logger::Log(LOG_DEBUG, sstream.str());

	// Read ICV
	_icv = std::vector<uint8_t>(ptr, ptr + icv_len_bytes);

	// Set output length
	len = hdr_len_bytes;

	return NO_ERROR;
}

uint8_t IPSecAuthHeader::GetNextHeader()
{
	return _next_hdr;
}

void IPSecAuthHeader::SetNextHeader(uint8_t next)
{
	_next_hdr = next;
}

uint8_t IPSecAuthHeader::GetLengthBytes()
{
	// Pad length of ICV to 32-bit boundary
	size_t icv_len_bytes = _icv.size();
	icv_len_bytes = (((icv_len_bytes - 1) / sizeof(uint32_t)) + 1) * sizeof(uint32_t);

	return AH_MIN_LEN_BYTES + icv_len_bytes;
}

uint32_t IPSecAuthHeader::GetSPI()
{
	return _spi;
}

void IPSecAuthHeader::SetSPI(uint32_t spi)
{
	_spi = spi;
}

uint32_t IPSecAuthHeader::GetSequenceNumber()
{
	return _seq_num;
}

void IPSecAuthHeader::SetSequenceNumber(uint32_t num)
{
	_seq_num = num;
}

size_t IPSecAuthHeader::GetICV(const uint8_t* &data)
{
	data = _icv.data();
	return _icv.size();
}

void IPSecAuthHeader::SetICV(const uint8_t *data, size_t len)
{
	_icv = std::vector<uint8_t>(data, data + len);
}
