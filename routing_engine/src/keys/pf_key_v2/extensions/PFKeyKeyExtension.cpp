#include "keys/pf_key_v2/extensions/PFKeyKeyExtension.hpp"
#include "status/error_codes.hpp"
#include <cstring>
#include "logging/Logger.hpp"

PFKeyKeyExtension::PFKeyKeyExtension()
	: _type(SADB_EXT_KEY_AUTH),
      _bits(0),
      _key_data()
{
}

/*
PFKeyKeyExtension::PFKeyKeyExtension(const PFKeyKeyExtension &rhs)
{
	_type = rhs._type;
	_bits = rhs._bits;
	_key_data = rhs._key_data;
}
*/

PFKeyKeyExtension::~PFKeyKeyExtension()
{
}

PFKeyKeyExtension& PFKeyKeyExtension::operator=(const PFKeyKeyExtension &rhs)
{
	_type = rhs._type;
	_bits = rhs._bits;
	_key_data = rhs._key_data;

	return *this;
}

int PFKeyKeyExtension::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	// Do not serialize if data is invalid
	if (!IsValid())
	{
		return PF_KEY_ERROR_MALFORMED_EXTENSION;
	}

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_key))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write data for base extension
	// Length will be written later
	struct sadb_key *ext_base = (struct sadb_key*)(buff + offset);
	ext_base->sadb_key_exttype = _type;
	ext_base->sadb_key_bits = _bits;
	offset += sizeof(struct sadb_key);

	// Verify enough data to write key data
	if (len < offset + _key_data.size())
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	size_t key_len_bytes = _key_data.size();
	memcpy(buff + offset, _key_data.data(), key_len_bytes);

	// Round key length to 64-bit boundary
	key_len_bytes = (((key_len_bytes - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);
	offset += key_len_bytes;

	// Set message length, in 64-bit words
	// Note that at this point, number of bytes is 64-bit aligned
	ext_base->sadb_key_len = offset / sizeof(uint64_t);

	// Set number of bytes output
	len = offset;

	return NO_ERROR;
}

int PFKeyKeyExtension::Deserialize(const uint8_t *data, size_t &len)
{
	size_t offset = 0;

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_key))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from base extension
	const struct sadb_key *ext_base = (const struct sadb_key*)(data + offset);
	_type = ext_base->sadb_key_exttype;
	_bits = ext_base->sadb_key_bits;
	offset += sizeof(struct sadb_key);

	// Verify enough bytes for stated length
	size_t ext_len_bytes = ext_base->sadb_key_len * sizeof(uint64_t);
	if (len < ext_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Verify enough data for stated number of bits
	size_t key_len_bytes = (((_bits - 1) / 8) + 1);
	if (len < offset + key_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read key data
	_key_data = std::vector<uint8_t>(data + offset, data + offset + key_len_bytes);

	// Set number of bytes consumed
	len = ext_len_bytes;

	return NO_ERROR;
}

size_t PFKeyKeyExtension::GetLengthBytes()
{
	// Round key length to 64-bit boundary
	size_t key_len_bytes = _key_data.size();
	key_len_bytes = (((key_len_bytes - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);

	return sizeof(struct sadb_key) + key_len_bytes;
}

uint16_t PFKeyKeyExtension::GetType()
{
	return _type;
}

bool PFKeyKeyExtension::IsValid()
{
	// Verify bit number is non-zero
	if (_bits == 0)
	{
		return false;
	}

	// Verify there are enough bytes in
	// the key to cover the number of bits
	size_t key_len_bytes = ((((_bits / 8) - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);
	if (_key_data.size() < key_len_bytes)
	{
		return false;
	}

	return true;
}

void PFKeyKeyExtension::SetTypeAuth()
{
	_type = SADB_EXT_KEY_AUTH;
}

void PFKeyKeyExtension::SetTypeEncrypt()
{
	_type = SADB_EXT_KEY_ENCRYPT;
}

size_t PFKeyKeyExtension::GetKeyData(const uint8_t* &data)
{
	data = _key_data.data();
	return _key_data.size();
}

uint16_t PFKeyKeyExtension::GetNumKeyBits()
{
	return _bits;
}

void PFKeyKeyExtension::SetKeyData(const uint8_t *data, size_t len, uint16_t bits)
{
	_key_data = std::vector<uint8_t>(data, data + len);
	_bits = bits;
}
