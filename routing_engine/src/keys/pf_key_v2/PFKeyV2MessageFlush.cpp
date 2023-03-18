#include "keys/pf_key_v2/PFKeyV2MessageFlush.hpp"
#include "status/error_codes.hpp"
#include <cstring>

PFKeyV2MessageFlush::PFKeyV2MessageFlush()
	: PFKeyV2MessageBase()
{
}

PFKeyV2MessageFlush::~PFKeyV2MessageFlush()
{
}

int PFKeyV2MessageFlush::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	////////////////////////////////
	////////// Base Header /////////
	////////////////////////////////

	// Ensure room for base header
	if (len < offset + sizeof(struct sadb_msg))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Build base header
	struct sadb_msg *hdr = (struct sadb_msg*)(buff + offset);
	memset(hdr, 0, sizeof(struct sadb_msg));

	hdr->sadb_msg_version = PF_KEY_V2;
	hdr->sadb_msg_type = SADB_ACQUIRE;
	hdr->sadb_msg_errno = _err_code;
	hdr->sadb_msg_satype = _sa_type;
	// Write length later
	hdr->sadb_msg_seq = _seq_num;
	hdr->sadb_msg_pid = _pid;
	offset += sizeof(sadb_msg);

	hdr->sadb_msg_len = offset / sizeof(uint64_t);

	return NO_ERROR;
}

int PFKeyV2MessageFlush::Deserialize(const uint8_t *data, size_t len)
{
	size_t offset = 0;

	// Ensure room for base header
	if (len < offset + sizeof(struct sadb_msg))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Build base header
	const struct sadb_msg *hdr = (const struct sadb_msg*)(data + offset);

	offset += sizeof(sadb_msg);
	_err_code = hdr->sadb_msg_errno;
	_sa_type = hdr->sadb_msg_satype;
	_seq_num = hdr->sadb_msg_seq;
	_pid = hdr->sadb_msg_pid;

	return NO_ERROR;
}

uint8_t PFKeyV2MessageFlush::GetMessageType()
{
	return SADB_FLUSH;
}
