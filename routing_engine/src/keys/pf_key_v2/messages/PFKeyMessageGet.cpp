#include "keys/pf_key_v2/messages/PFKeyMessageGet.hpp"
#include <cstring>
#include "status/error_codes.hpp"

PFKeyMessageGet::PFKeyMessageGet()
	: _assoc(),
	  _src(),
	  _dst(),
	  _proxy(),
	  _auth_key(),
	  _encrypt_key(),
	  _src_id(),
	  _dst_id(),
	  _proxy_present(false),
	  _auth_key_present(false),
	  _encrypt_key_present(false),
	  _src_id_present(false),
	  _dst_id_present(false)
{
	memset(&_header, 0, sizeof(struct sadb_msg));
	_header.sadb_msg_type = SADB_GET;
	_header.sadb_msg_version = PF_KEY_V2;
	_header.sadb_msg_satype = SADB_SATYPE_AH;
}

PFKeyMessageGet::~PFKeyMessageGet()
{
}

uint8_t PFKeyMessageGet::GetMessageType()
{
	return SADB_GET;
}

size_t PFKeyMessageGet::GetLengthBytes()
{
	size_t total_len_bytes = sizeof(struct sadb_msg);

	total_len_bytes += _assoc.GetLengthBytes();
	total_len_bytes += _src.GetLengthBytes();
	total_len_bytes += _dst.GetLengthBytes();
	total_len_bytes += (_proxy_present) ? _proxy.GetLengthBytes() : 0;
	total_len_bytes += (_auth_key_present) ? _auth_key.GetLengthBytes() : 0;
	total_len_bytes += (_encrypt_key_present) ? _encrypt_key.GetLengthBytes() : 0;
	total_len_bytes += (_src_id_present) ? _src_id.GetLengthBytes() : 0;
	total_len_bytes += (_dst_id_present) ? _dst_id.GetLengthBytes() : 0;

	return total_len_bytes;
}

int PFKeyMessageGet::Serialize(uint8_t *buff, size_t &len)
{
	int status = NO_ERROR;
	size_t offset = 0;
	size_t ext_len;

	// Verify enough data for base header
	if (len < sizeof(struct sadb_msg))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write base header
	struct sadb_msg *_header_out = (struct sadb_msg*)(buff);
	memcpy(buff, &_header, sizeof(struct sadb_msg));
	offset += sizeof(struct sadb_msg);

	// Write Assocation
	ext_len = len - offset;
	status = _assoc.Serialize(buff + offset, ext_len);
	if (status != NO_ERROR)
	{
		return status;
	}
	offset += ext_len;

	// Write Source Address
	ext_len = len - offset;
	status = _src.Serialize(buff + offset, ext_len);
	if (status != NO_ERROR)
	{
		return status;
	}
	offset += ext_len;

	// Write Destination Address
	ext_len = len - offset;
	status = _dst.Serialize(buff + offset, ext_len);
	if (status != NO_ERROR)
	{
		return status;
	}
	offset += ext_len;

	// Write Proxy Address, if present
	if (_proxy_present)
	{
		ext_len = len - offset;
		status = _proxy.Serialize(buff + offset, ext_len);
		if (status != NO_ERROR)
		{
			return status;
		}
		offset += ext_len;
	}

	// Write Authentication Key, if present
	if (_auth_key_present)
	{
		ext_len = len - offset;
		status = _auth_key.Serialize(buff + offset, ext_len);
		if (status != NO_ERROR)
		{
			return status;
		}
		offset += ext_len;
	}

	// Write Encryption Key, if present
	if (_encrypt_key_present)
	{
		ext_len = len - offset;
		status = _encrypt_key.Serialize(buff + offset, ext_len);
		if (status != NO_ERROR)
		{
			return status;
		}
		offset += ext_len;
	}

	// Write Source ID, if present
	if (_src_id_present)
	{
		ext_len = len - offset;
		status = _src_id.Serialize(buff + offset, ext_len);
		if (status != NO_ERROR)
		{
			return status;
		}
		offset += ext_len;
	}

	// Write Destination ID, if present
	if (_dst_id_present)
	{
		ext_len = len - offset;
		status = _dst_id.Serialize(buff + offset, ext_len);
		if (status != NO_ERROR)
		{
			return status;
		}
		offset += ext_len;
	}

	// Write final length of message
	// Note that each extension is guaranteed to return
	// a 64-bit aligned length, so the final offset
	// is guaranteed to be 64-bit aligned
	_header_out->sadb_msg_len = offset / sizeof(uint64_t);

	// Set length output
	len = offset;

	return NO_ERROR;
}

int PFKeyMessageGet::Deserialize(const uint8_t *data, size_t len)
{
	int status = NO_ERROR;
	size_t offset = 0;

	// Verify enough data for base header
	if (len < sizeof(struct sadb_msg))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from header
	memcpy(&_header, data, sizeof(struct sadb_msg));
	offset += sizeof(struct sadb_msg);

	// Verify enough data for stated length
	size_t msg_len_bytes = _header.sadb_msg_len * sizeof(uint64_t);
	if (len < msg_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Keep track of required extensions
	bool _assoc_present = false;
	bool _src_present = false;
	bool _dst_present = false;

	// Deserialize each extension
	while (offset < len)
	{
		// Verify enough data for extension base
		if (len < offset + sizeof(struct sadb_ext))
		{
			return PF_KEY_ERROR_OVERFLOW;
		}

		struct sadb_ext *ext = (struct sadb_ext*)(data + offset);
		size_t ext_len = len - offset; // Amount of data remaining

		// Populate appropriate structure based on extension type
		switch (ext->sadb_ext_type)
		{
			case SADB_EXT_SA:
			{
				status = _assoc.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_assoc_present = true;
				break;
			}
			case SADB_EXT_ADDRESS_SRC:
			{
				status = _src.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_src_present = true;
				break;
			}
			case SADB_EXT_ADDRESS_DST:
			{
				status = _dst.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_dst_present = true;
				break;
			}
			case SADB_EXT_ADDRESS_PROXY:
			{
				status = _proxy.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_proxy_present = true;
				break;
			}
			case SADB_EXT_KEY_AUTH:
			{
				status = _auth_key.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_auth_key_present = true;
				break;
			}
			case SADB_EXT_KEY_ENCRYPT:
			{
				status = _encrypt_key.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_encrypt_key_present = true;
				break;
			}
			case SADB_EXT_IDENTITY_SRC:
			{
				status = _src_id.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_src_id_present = true;
				break;
			}
			case SADB_EXT_IDENTITY_DST:
			{
				status = _dst_id.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_dst_id_present = true;
				break;
			}
			default:
			{
				// Unknown/unimplemented extension. Skip
				break;
			}
		}

		// Move pointer forward by length of extension
		offset += ext->sadb_ext_len * sizeof(uint64_t);
	}

	// Check for required extensions
	if (!_assoc_present || !_src_present || !_dst_present)
	{
		return PF_KEY_ERROR_MISSING_EXTENSION;
	}

	return NO_ERROR;
}

PFKeyAssociationExtension& PFKeyMessageGet::Association()
{
	return _assoc;
}

PFKeyAddressExtension& PFKeyMessageGet::SourceAddress()
{
	return _src;
}

PFKeyAddressExtension& PFKeyMessageGet::DestinationAddress()
{
	return _dst;
}

PFKeyAddressExtension& PFKeyMessageGet::ProxyAddress()
{
	return _proxy;
}

PFKeyKeyExtension& PFKeyMessageGet::AuthKey()
{
	return _auth_key;
}

PFKeyKeyExtension& PFKeyMessageGet::EncryptKey()
{
	return _encrypt_key;
}

PFKeyIdentityExtension& PFKeyMessageGet::SourceID()
{
	return _src_id;
}

PFKeyIdentityExtension& PFKeyMessageGet::DestinationID()
{
	return _dst_id;
}

void PFKeyMessageGet::SetProxyAddressPresent(bool present)
{
	_proxy_present = present;
}

void PFKeyMessageGet::SetAuthKeyPresent(bool present)
{
	_auth_key_present = present;
}

void PFKeyMessageGet::SetEncryptKeyPresent(bool present)
{
	_encrypt_key_present = present;
}

void PFKeyMessageGet::SetSourceIDPresent(bool present)
{
	_src_id_present = present;
}

void PFKeyMessageGet::SetDestinationIDPresent(bool present)
{
	_dst_id_present = present;
}

bool PFKeyMessageGet::GetProxyAddressPresent()
{
	return _proxy_present;
}

bool PFKeyMessageGet::GetAuthKeyPresent()
{
	return _auth_key_present;
}

bool PFKeyMessageGet::GetEncryptKeyPresent()
{
	return _encrypt_key_present;
}

bool PFKeyMessageGet::GetSourceIDPresent()
{
	return _src_id_present;
}

bool PFKeyMessageGet::GetDestinationIDPresent()
{
	return _dst_id_present;
}
