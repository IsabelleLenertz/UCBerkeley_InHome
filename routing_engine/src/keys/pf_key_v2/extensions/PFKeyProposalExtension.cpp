#include "keys/pf_key_v2/extensions/PFKeyProposalExtension.hpp"
#include "status/error_codes.hpp"
#include <cstring>

#include "logging/Logger.hpp"

PFKeyProposalExtension::PFKeyProposalExtension()
	: _window(0),
	  _combs()
{
}

/*
PFKeyProposalExtension::PFKeyProposalExtension(const PFKeyProposalExtension &rhs)
{
	_window = rhs._window;
	_combs = rhs._combs;
}
*/

PFKeyProposalExtension::~PFKeyProposalExtension()
{
}

PFKeyProposalExtension& PFKeyProposalExtension::operator=(const PFKeyProposalExtension &rhs)
{
	_window = rhs._window;
	_combs = rhs._combs;

	return *this;
}

int PFKeyProposalExtension::Serialize(uint8_t *buff, size_t &len)
{
	size_t offset = 0;

	// Do not serialize if data is invalid
	if (!IsValid())
	{
		return PF_KEY_ERROR_MALFORMED_EXTENSION;
	}

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_prop))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write data for base extension
	// Length will be written later
	struct sadb_prop *ext_base = (struct sadb_prop*)(buff + offset);
	ext_base->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	ext_base->sadb_prop_replay = _window;
	offset += sizeof(struct sadb_prop);

	// Verify enough room for all proposed combinations
	if (len < offset + (_combs.size() * sizeof(struct sadb_comb)))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Write combinations
	for (auto e = _combs.begin(); e < _combs.end(); e++)
	{
		struct sadb_comb &entry = *e;
		memcpy(buff + offset, &entry, sizeof(struct sadb_comb));
		offset += sizeof(struct sadb_comb);
	}

	// Set message length, in 64-bit words
	// Note that at this point, number of bytes is 64-bit aligned
	ext_base->sadb_prop_len = offset / sizeof(uint64_t);

	// Set number of bytes output
	len = offset;

	return NO_ERROR;
}

int PFKeyProposalExtension::Deserialize(const uint8_t *data, size_t &len)
{
	std::stringstream sstream;
	size_t offset = 0;

	// Verify enough data for base extension
	if (len < sizeof(struct sadb_prop))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read data from base extension
	const struct sadb_prop *ext_base = (const struct sadb_prop*)(data + offset);
	_window = ext_base->sadb_prop_replay;
	offset += sizeof(struct sadb_prop);

	// Verify enough bytes for stated length
	size_t ext_len_bytes = ext_base->sadb_prop_len * sizeof(uint64_t);

	// Calculate number of combinations in message
	size_t num_combs = (ext_len_bytes - sizeof(struct sadb_prop)) / sizeof(struct sadb_comb);

	if (len < ext_len_bytes)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Read combinations
	_combs.clear();
	for (int i = 0; i < num_combs; i++)
	{
		const struct sadb_comb *comb = (const struct sadb_comb*)(data + offset);
		_combs.push_back(*comb);
		offset += sizeof(struct sadb_comb);
	}

	// Set number of bytes consumed
	len = ext_len_bytes;

	return NO_ERROR;
}

size_t PFKeyProposalExtension::GetLengthBytes()
{
	return sizeof(struct sadb_prop) + (_combs.size() * sizeof(struct sadb_comb));
}

uint16_t PFKeyProposalExtension::GetType()
{
	return SADB_EXT_PROPOSAL;
}

bool PFKeyProposalExtension::IsValid()
{
	if (_combs.size() == 0)
	{
		return false;
	}

	return true;
}

uint8_t PFKeyProposalExtension::GetReplayWindow()
{
	return _window;
}

void PFKeyProposalExtension::SetReplayWindow(uint8_t window)
{
	_window = window;
}

void PFKeyProposalExtension::AddCombination(const struct sadb_comb comb)
{
	_combs.push_back(comb);
}

size_t PFKeyProposalExtension::GetCombinationCount()
{
	return _combs.size();
}

struct sadb_comb *PFKeyProposalExtension::GetCombinationAt(size_t index)
{
	if (index < 0 || index > _combs.size() - 1)
	{
		return nullptr;
	}

	return &(*(_combs.begin() + index));
}

void PFKeyProposalExtension::RemoveCombinationAt(size_t index)
{
	if (index < 0 || index > _combs.size() - 1)
	{
		return;
	}

	auto it = _combs.begin() + index;
	_combs.erase(it);
}
