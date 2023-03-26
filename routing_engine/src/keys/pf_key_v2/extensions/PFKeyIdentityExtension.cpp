#include "keys/pf_key_v2/extensions/PFKeyIdentityExtension.hpp"
#include "status/error_codes.hpp"
#include <cstring>

#include "logging/Logger.hpp"

PFKeyIdentityExtension::PFKeyIdentityExtension()
	: _type(SADB_EXT_IDENTITY_SRC),
      _id_type(SADB_IDENTTYPE_RESERVED),
      _id_num(0),
      _id_string()
{
}

/*
PFKeyIdentityExtension::PFKeyIdentityExtension(const PFKeyIdentityExtension &rhs)
{
	_type = rhs._type;
	_id_type = rhs._id_type;
	_id_num = rhs._id_num;
	_id_string = rhs._id_string;
}
*/

PFKeyIdentityExtension::~PFKeyIdentityExtension()
{
}

PFKeyIdentityExtension& PFKeyIdentityExtension::operator=(const PFKeyIdentityExtension &rhs)
{
	_type = rhs._type;
	_id_type = rhs._id_type;
	_id_num = rhs._id_num;
	_id_string = rhs._id_string;

	return *this;
}

int PFKeyIdentityExtension::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	// Do not serialize if data is invalid
	if (!IsValid())
	{
		return PF_KEY_ERROR_MALFORMED_EXTENSION;
	}

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_ident))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write data for base extension
	// Length will be written later
	struct sadb_ident *ext_base = (struct sadb_ident*)(buff + offset);
	ext_base->sadb_ident_exttype = _type;
	ext_base->sadb_ident_type = _id_type;
	ext_base->sadb_ident_id = _id_num;
	offset += sizeof(struct sadb_ident);

	// Write ID string data, if present
	if (_id_string.size() > 0)
	{
		// The ID string to be written is a C string
		// The storage length is the length of the
		// string plus 1, for the null character
		size_t id_strlen_bytes = _id_string.size() + 1;

		// Round to 64-byte boundary
		id_strlen_bytes = (((id_strlen_bytes - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);

		// Verify enough data to write ID string
		// This quantity includes the null character
		if (len < offset + id_strlen_bytes)
		{
			return PF_KEY_ERROR_OVERFLOW;
		}

		// Clear data to zero-pad ID string
		memset(buff + offset, 0, id_strlen_bytes);

		// Write string data, including null character
		memcpy(buff + offset, _id_string.c_str(), id_strlen_bytes);
		offset += id_strlen_bytes;
	}

	// Set message length, in 64-bit words
	// Note that at this point, number of bytes is 64-bit aligned
	ext_base->sadb_ident_len = offset / sizeof(uint64_t);

	// Set number of bytes output
	len = offset;

	return NO_ERROR;
}

int PFKeyIdentityExtension::Deserialize(const uint8_t *data, size_t &len)
{
	size_t offset = 0;

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_ident))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from base extension
	const struct sadb_ident *ext_base = (const struct sadb_ident*)(data + offset);
	_type = ext_base->sadb_ident_exttype;
	_id_type = ext_base->sadb_ident_type;
	_id_num = ext_base->sadb_ident_id;
	offset += sizeof(struct sadb_ident);

	// Verify enough bytes for stated length
	size_t ext_len_bytes = ext_base->sadb_ident_len * sizeof(uint64_t);
	if (len < ext_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Check if there is an ID string present
	if (offset < ext_len_bytes)
	{
		// Check all characters from the last character
		// of the extension back to the first character
		// after the base header
		// If none of these values is the null-character
		// then the string is not null-terminated
		const char *c = (const char *)(data + (ext_len_bytes - 1));
		bool null_terminated = false;
		while (c >= (const char *)(data + offset))
		{
			if (*c == '\0')
			{
				null_terminated = true;
				break;
			}
			c--;
		}

		// Return overflow error, since attempting
		// to read a null-terminated string would
		// overflow the extension data
		if (!null_terminated)
		{
			return PF_KEY_ERROR_OVERFLOW;
		}

		// Read ID string. At this point, the string is
		// guaranteed to be null-terminated. Note that this
		// does not guarantee that the string represents
		// a valid ID, nor does this guarantee that there are
		// no control characters in the string.
		_id_string = std::string((const char *)(data + offset));
	}

	// Set number of bytes consumed
	len = ext_len_bytes;

	return NO_ERROR;
}

size_t PFKeyIdentityExtension::GetLengthBytes()
{
	// If the ID string is empty, then no bytes
	// should be written for the ID string
	size_t id_strlen_bytes = 0;
	if (_id_string.size() > 0)
	{
		// The ID string to be written is a C string
		// The storage length is the length of the
		// string plus 1, for the null character
		id_strlen_bytes = _id_string.size() + 1;

		// Round to 64-byte boundary
		id_strlen_bytes = (((id_strlen_bytes - 1) / sizeof(uint64_t)) + 1) * sizeof(uint64_t);
	}

	return (sizeof(sadb_ident) + id_strlen_bytes);
}

uint16_t PFKeyIdentityExtension::GetType()
{
	return _type;
}

bool PFKeyIdentityExtension::IsValid()
{
	// Verify that the ID type is valid
	// These values are taken from RFC 2367
	if (_id_type != SADB_IDENTTYPE_PREFIX &&
		_id_type != SADB_IDENTTYPE_FQDN &&
		_id_type != SADB_IDENTTYPE_USERFQDN)
	{
		return false;
	}

	return true;
}

void PFKeyIdentityExtension::SetTypeSource()
{
	_type = SADB_EXT_IDENTITY_SRC;
}

void PFKeyIdentityExtension::SetTypeDestination()
{
	_type = SADB_EXT_IDENTITY_DST;
}

uint16_t PFKeyIdentityExtension::GetIDType()
{
	return _id_type;
}

void PFKeyIdentityExtension::SetIDType(uint16_t id_type)
{
	_id_type = id_type;
}

uint64_t PFKeyIdentityExtension::GetIDNumber()
{
	return _id_num;
}

void PFKeyIdentityExtension::SetIDNumber(uint64_t id_num)
{
	_id_num = id_num;
}

const char * PFKeyIdentityExtension::GetIDString()
{
	return _id_string.c_str();
}

void PFKeyIdentityExtension::SetIDString(const char *id_string)
{
	_id_string = std::string(id_string);
}
