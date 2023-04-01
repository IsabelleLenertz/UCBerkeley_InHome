#include "keys/pf_key_v2/messages/PFKeyMessageAcquire.hpp"
#include <cstring>
#include "status/error_codes.hpp"

#include "logging/Logger.hpp"

PFKeyMessageAcquire::PFKeyMessageAcquire()
	: _src(),
	  _dst(),
	  _proxy(),
	  _src_id(),
	  _dst_id(),
	  _proposal(),
	  _proxy_present(false),
	  _src_id_present(false),
	  _dst_id_present(false)
{
	memset(&_header, 0, sizeof(struct sadb_msg));
	_header.sadb_msg_type = SADB_ACQUIRE;
	_header.sadb_msg_version = PF_KEY_V2;
	_header.sadb_msg_satype = SADB_SATYPE_AH;
}

PFKeyMessageAcquire::PFKeyMessageAcquire(const PFKeyMessageAcquire &rhs)
{
}

PFKeyMessageAcquire::~PFKeyMessageAcquire()
{
}

uint8_t PFKeyMessageAcquire::GetMessageType()
{
	return SADB_ACQUIRE;
}

size_t PFKeyMessageAcquire::GetLengthBytes()
{
	size_t total_len_bytes = sizeof(struct sadb_msg);

	total_len_bytes += _src.GetLengthBytes();
	total_len_bytes += _dst.GetLengthBytes();
	total_len_bytes += (_proxy_present) ? _proxy.GetLengthBytes() : 0;
	total_len_bytes += (_src_id_present) ? _src_id.GetLengthBytes() : 0;
	total_len_bytes += (_dst_id_present) ? _dst_id.GetLengthBytes() : 0;
	total_len_bytes += _proposal.GetLengthBytes();

	return total_len_bytes;
}

int PFKeyMessageAcquire::Serialize(uint8_t *buff, size_t &len)
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

	// Write Proposal
	ext_len = len - offset;
	status = _proposal.Serialize(buff + offset, ext_len);
	if (status != NO_ERROR)
	{
		return status;
	}
	offset += ext_len;

	// Write final length of message
	// Note that each extension is guaranteed to return
	// a 64-bit aligned length, so the final offset
	// is guaranteed to be 64-bit aligned
	_header_out->sadb_msg_len = offset / sizeof(uint64_t);

	// TEST
	_header_out->sadb_msg_len = sizeof(sadb_msg) / 8;

	// Set length output
	len = offset;

	PrintInfo();

	return NO_ERROR;
}

int PFKeyMessageAcquire::Deserialize(const uint8_t *data, size_t len)
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
	bool _src_present = false;
	bool _dst_present = false;
	bool _proposal_present = false;

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
			case SADB_EXT_PROPOSAL:
			{
				status = _proposal.Deserialize(data + offset, ext_len);
				if (status != NO_ERROR)
				{
					return status;
				}
				_proposal_present = true;
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

	PrintInfo();

	return NO_ERROR;
}

PFKeyAddressExtension& PFKeyMessageAcquire::SourceAddress()
{
	return _src;
}

PFKeyAddressExtension& PFKeyMessageAcquire::DestinationAddress()
{
	return _dst;
}

PFKeyAddressExtension& PFKeyMessageAcquire::ProxyAddress()
{
	return _proxy;
}

PFKeyIdentityExtension& PFKeyMessageAcquire::SourceID()
{
	return _src_id;
}

PFKeyIdentityExtension& PFKeyMessageAcquire::DestinationID()
{
	return _dst_id;
}

PFKeyProposalExtension& PFKeyMessageAcquire::Proposal()
{
	return _proposal;
}

void PFKeyMessageAcquire::SetProxyAddressPresent(bool present)
{
	_proxy_present = present;
}

void PFKeyMessageAcquire::SetSourceIDPresent(bool present)
{
	_src_id_present = present;
}

void PFKeyMessageAcquire::SetDestinationIDPresent(bool present)
{
	_dst_id_present = present;
}

bool PFKeyMessageAcquire::GetProxyAddressPresent()
{
	return _proxy_present;
}

bool PFKeyMessageAcquire::GetSourceIDPresent()
{
	return _src_id_present;
}

bool PFKeyMessageAcquire::GetDestinationIDPresent()
{
	return _dst_id_present;
}

void PFKeyMessageAcquire::PrintInfo()
{
	std::stringstream sstream;

	sstream.str("");
	sstream << "SA Type: " << +_header.sadb_msg_satype;
	Logger::Log(LOG_VERBOSE, sstream.str());

	sstream.str("");
	sstream << "Sequence number: " << _header.sadb_msg_seq;
	Logger::Log(LOG_VERBOSE, sstream.str());

	sstream.str("");
	sstream << "PID: " << _header.sadb_msg_pid;
	Logger::Log(LOG_VERBOSE, sstream.str());

	sstream.str("");
	sstream << "Source Address: " << Logger::IPToString(_src.GetAddress()) << "/" << +_src.GetPrefixLength() << " (" << +_src.GetProtocol() << ")";
	Logger::Log(LOG_VERBOSE, sstream.str());

	sstream.str("");
	sstream << "Destination Address: " << Logger::IPToString(_dst.GetAddress()) << "/" << +_dst.GetPrefixLength() << " (" << +_dst.GetProtocol() << ")";
	Logger::Log(LOG_VERBOSE, sstream.str());

	if (_proxy_present)
	{
		sstream.str("");
		sstream << "Proxy Address: " << Logger::IPToString(_proxy.GetAddress()) << "/" << +_proxy.GetPrefixLength() << " (" << +_proxy.GetProtocol() << ")";
		Logger::Log(LOG_VERBOSE, sstream.str());
	}

	if (_src_id_present)
	{
		sstream.str("");
		sstream << "Source ID: " << _src_id.GetIDString() << " (" << _src_id.GetIDNumber() << ")";
		Logger::Log(LOG_VERBOSE, sstream.str());
	}

	if (_dst_id_present)
	{
		sstream.str("");
		sstream << "Source ID: " << _dst_id.GetIDString() << " (" << _dst_id.GetIDNumber() << ")";
		Logger::Log(LOG_VERBOSE, sstream.str());
	}
}
