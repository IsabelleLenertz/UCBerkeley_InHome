#include "keys/pf_key_v2/extensions/PFKeyAddressExtension.hpp"
#include "status/error_codes.hpp"
#include <cstring>

PFKeyAddressExtension::PFKeyAddressExtension()
	: _addr(),
	  _type(SADB_EXT_ADDRESS_SRC),
	  _prefix_len(0),
	  _protocol(0)
{
}

/*
PFKeyAddressExtension::PFKeyAddressExtension(const PFKeyAddressExtension &rhs)
{
	IPUtils::StoreSockaddr(reinterpret_cast<const sockaddr&>(rhs._addr), _addr);
	_type = rhs._type;
	_prefix_len = rhs._prefix_len;
	_protocol = rhs._protocol;
}
*/

PFKeyAddressExtension::~PFKeyAddressExtension()
{
}

PFKeyAddressExtension& PFKeyAddressExtension::operator=(const PFKeyAddressExtension &rhs)
{
	IPUtils::StoreSockaddr(reinterpret_cast<const sockaddr&>(rhs._addr), _addr);
	_type = rhs._type;
	_prefix_len = rhs._prefix_len;
	_protocol = rhs._protocol;

	return *this;
}

int PFKeyAddressExtension::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	// Do not serialize if data is invalid
	if (!IsValid())
	{
		return PF_KEY_ERROR_MALFORMED_EXTENSION;
	}

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_address))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write data for base extension
	// Length will be written later
	struct sadb_address *ext_base = (struct sadb_address*)(buff + offset);
	ext_base->sadb_address_exttype = _type;
	ext_base->sadb_address_proto = _protocol;
	ext_base->sadb_address_prefixlen = _prefix_len;
	offset += sizeof(struct sadb_address);

	// Get size of address to be written
	const struct sockaddr &addr = reinterpret_cast<const sockaddr&>(_addr);
	size_t addrlen = IPUtils::GetAddressSize(addr);
	if (addrlen == 0)
	{
		return PF_KEY_ERROR_UNSUPPORTED_PROTOCOL;
	}

	// Verify enough data to write address
	if (len < offset + addrlen)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Round address length to 64-bit boundary
	addrlen = (((addrlen - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);

	// Clear memory so address is zero-padded
	memset(buff + offset, 0, addrlen);

	// Copy address to output
	struct sockaddr *addr_out = (struct sockaddr*)(buff + offset);
	IPUtils::CopySockaddr(addr, *addr_out);
	offset += addrlen;

	// Set message length, in 64-bit words
	// Note that at this point, number of bytes is 64-bit aligned
	ext_base->sadb_address_len = offset / sizeof(uint64_t);

	// Set number of bytes output
	len = offset;

	return NO_ERROR;
}

int PFKeyAddressExtension::Deserialize(const uint8_t *data, size_t &len)
{
	size_t offset = 0;

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_address))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from base extension
	const struct sadb_address *ext_base = (const struct sadb_address*)(data + offset);
	_type = ext_base->sadb_address_exttype;
	_protocol = ext_base->sadb_address_proto;
	_prefix_len = ext_base->sadb_address_prefixlen;
	offset += sizeof(struct sadb_address);

	// Verify enough bytes for stated length
	size_t ext_len_bytes = ext_base->sadb_address_len * sizeof(uint64_t);
	if (len < ext_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Verify enough data to read address family
	size_t sockaddr_len_bytes = ext_len_bytes - sizeof(struct sadb_address);
	if (sockaddr_len_bytes < sizeof(uint16_t))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Get expected length for address family
	const struct sockaddr *addr = reinterpret_cast<const sockaddr*>(data + offset);
	size_t addrlen = IPUtils::GetAddressSize(*addr);
	if (addrlen == 0)
	{
		return PF_KEY_ERROR_UNSUPPORTED_PROTOCOL;
	}

	// Verify enough bytes to read full address
	if (sockaddr_len_bytes < addrlen)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Store socket address
	IPUtils::StoreSockaddr(*addr, _addr);

	// Set number of bytes consumed
	len = ext_len_bytes;

	return NO_ERROR;
}

size_t PFKeyAddressExtension::GetLengthBytes()
{
	// Get size of corresponding socket address
	size_t addrlen;
	switch (_addr.ss_family)
	{
		case AF_INET:
		{
			addrlen = sizeof(struct sockaddr_in);
			break;
		}
		case AF_INET6:
		{
			addrlen = sizeof(struct sockaddr_in6);
			break;
		}
		default:
		{
			addrlen = 0;
			break;
		}
	}

	// Add size of header and size of socket address
	return sizeof(struct sadb_address) + addrlen;
}

uint16_t PFKeyAddressExtension::GetType()
{
	return _type;
}

bool PFKeyAddressExtension::IsValid()
{
	if (_addr.ss_family != AF_INET && _addr.ss_family != AF_INET6)
	{
		// Not supporting non-IP address families
		return false;
	}

	return true;
}

void PFKeyAddressExtension::SetTypeSource()
{
	_type = SADB_EXT_ADDRESS_SRC;
}

void PFKeyAddressExtension::SetTypeDestination()
{
	_type = SADB_EXT_ADDRESS_DST;
}

void PFKeyAddressExtension::SetTypeProxy()
{
	_type = SADB_EXT_ADDRESS_PROXY;
}

const struct sockaddr &PFKeyAddressExtension::GetAddress()
{
	return reinterpret_cast<const struct sockaddr&>(_addr);
}

void PFKeyAddressExtension::SetAddress(const struct sockaddr &addr)
{
	IPUtils::StoreSockaddr(addr, _addr);
}

uint8_t PFKeyAddressExtension::GetPrefixLength()
{
	return _prefix_len;
}

void PFKeyAddressExtension::SetPrefixLength(uint8_t prefix_len)
{
	_prefix_len = prefix_len;
}

uint8_t PFKeyAddressExtension::GetProtocol()
{
	return _protocol;
}

void PFKeyAddressExtension::SetProtocol(uint8_t protocol)
{
	_protocol = protocol;
}
