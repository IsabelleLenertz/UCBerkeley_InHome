#include "keys/pf_key_v2/extensions/PFKeyAssociationExtension.hpp"
#include "status/error_codes.hpp"
#include <cstring>

PFKeyAssociationExtension::PFKeyAssociationExtension()
{
	_sa.sadb_sa_len = sizeof(struct sadb_sa) / sizeof(uint64_t);
	_sa.sadb_sa_exttype = SADB_EXT_SA;
	_sa.sadb_sa_spi = 0;
	_sa.sadb_sa_replay = 0;
	_sa.sadb_sa_state = SADB_SASTATE_LARVAL;
	_sa.sadb_sa_auth = SADB_AALG_NONE;
	_sa.sadb_sa_encrypt = SADB_EALG_NONE;
	_sa.sadb_sa_flags = 0;
}

PFKeyAssociationExtension::~PFKeyAssociationExtension()
{
}

int PFKeyAssociationExtension::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	// Do not serialize if data is invalid
	if (!IsValid())
	{
		return PF_KEY_ERROR_MALFORMED_EXTENSION;
	}

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_sa))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write base extension
	memcpy(buff + offset, &_sa, sizeof(struct sadb_sa));
	offset += sizeof(struct sadb_sa);

	// Set number of bytes output
	len = offset;

	return NO_ERROR;
}

int PFKeyAssociationExtension::Deserialize(const uint8_t *data, size_t &len)
{
	size_t offset = 0;

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_sa))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from base extension
	const struct sadb_sa *ext_base = (const struct sadb_sa*)(data + offset);
	memcpy(&_sa, ext_base, sizeof(struct sadb_sa));
	offset += sizeof(struct sadb_sa);

	// Verify enough bytes for stated length
	size_t ext_len_bytes = ext_base->sadb_sa_len * sizeof(uint64_t);
	if (len < ext_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Set number of bytes consumed
	len = ext_len_bytes;

	return NO_ERROR;
}

size_t PFKeyAssociationExtension::GetLengthBytes()
{
	return sizeof(struct sadb_sa);
}

uint16_t PFKeyAssociationExtension::GetType()
{
	return SADB_EXT_SA;
}

bool PFKeyAssociationExtension::IsValid()
{
	return true;
}

uint32_t PFKeyAssociationExtension::GetSPI()
{
	return _sa.sadb_sa_spi;
}

void PFKeyAssociationExtension::SetSPI(uint32_t spi)
{
	_sa.sadb_sa_spi = spi;
}

uint8_t PFKeyAssociationExtension::GetReplayWindow()
{
	return _sa.sadb_sa_replay;
}

void PFKeyAssociationExtension::SetReplayWindow(uint8_t window)
{
	_sa.sadb_sa_replay = window;
}

uint8_t PFKeyAssociationExtension::GetState()
{
	return _sa.sadb_sa_state;
}

void PFKeyAssociationExtension::SetState(uint8_t state)
{
	_sa.sadb_sa_state = state;
}

uint8_t PFKeyAssociationExtension::GetAuthAlgorithm()
{
	return _sa.sadb_sa_auth;
}

void PFKeyAssociationExtension::SetAuthAlgorithm(uint8_t alg)
{
	_sa.sadb_sa_auth = alg;
}

uint8_t PFKeyAssociationExtension::GetEncryptAlgorithm()
{
	return _sa.sadb_sa_encrypt;
}

void PFKeyAssociationExtension::SetEncryptAlgorithm(uint8_t alg)
{
	_sa.sadb_sa_encrypt = alg;
}

uint32_t PFKeyAssociationExtension::GetFlags()
{
	return _sa.sadb_sa_flags;
}

void PFKeyAssociationExtension::SetFlags(uint32_t flags)
{
	_sa.sadb_sa_flags = flags;
}
