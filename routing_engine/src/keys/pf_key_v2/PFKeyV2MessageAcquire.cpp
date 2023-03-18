#include "keys/pf_key_v2/PFKeyV2MessageAcquire.hpp"
#include "layer3/IPUtils.hpp"
#include "status/error_codes.hpp"

#include <cstring>

PFKeyV2MessageAcquire::~PFKeyV2MessageAcquire()
{
}

int PFKeyV2MessageAcquire::Serialize(uint8_t *buff, size_t &len)
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

	////////////////////////////////
	//////// Source Address ////////
	////////////////////////////////

	// Get length of source sockaddr in bytes
	size_t addr_len = (_src_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	// Get length of full address extension (including sockaddr), in 64-bit words
	size_t len64 = sizeof(struct sadb_address) + addr_len;
	len64 = (((len64 - 1) / sizeof(uint64_t)) + 1); // Round to 64-bit boundary

	// Verify enough room in output
	if (len < offset + (len64 * sizeof(uint64_t)))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Clear memory so it will be zero-padded
	memset(buff + offset, 0, len64 * sizeof(uint64_t));

	// Build source address extension header
	struct sadb_address *addr_ext = (struct sadb_address*)(buff + offset);
	addr_ext->sadb_address_len = len64;
	addr_ext->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addr_ext->sadb_address_proto = _src_protocol;
	addr_ext->sadb_address_prefixlen = _src_prefix;

	// Write socket address to output
	struct sockaddr *addr = (struct sockaddr*)(buff + offset + sizeof(struct sadb_address));
	IPUtils::CopySockaddr(reinterpret_cast<const struct sockaddr&>(_src_addr), *addr);
	offset += len64 * sizeof(uint64_t);

	////////////////////////////////
	///// Destination Address //////
	////////////////////////////////

	// Get length of destination sockaddr in bytes
	addr_len = (_src_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	// Get length of full address extension (including sockaddr), in 64-bit words
	len64 = sizeof(struct sadb_address) + addr_len;
	len64 = (((len64 - 1) / sizeof(uint64_t)) + 1); // Round to 64-bit boundary

	// Verify enough room in output
	if (len < offset + (len64 * sizeof(uint64_t)))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Clear memory so it will be zero-padded
	memset(buff + offset, 0, len64 * sizeof(uint64_t));

	// Build source address extension header
	addr_ext = (struct sadb_address*)(buff + offset);
	addr_ext->sadb_address_len = len64;
	addr_ext->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	addr_ext->sadb_address_proto = _dst_protocol;
	addr_ext->sadb_address_prefixlen = _dst_prefix;

	// Write socket address to output
	addr = (struct sockaddr*)(buff + offset + sizeof(struct sadb_address));
	IPUtils::CopySockaddr(reinterpret_cast<const struct sockaddr&>(_dst_addr), *addr);
	offset += len64 * sizeof(uint64_t);

	////////////////////////////////
	/////////// Proposal ///////////
	////////////////////////////////
	len64 = sizeof(struct sadb_prop) + (_combs.size() * sizeof(struct sadb_comb));
	len64 /= sizeof(uint64_t);
	// Note: sizeof(struct sadb_prop) and sizeof(struct sadb_comb) are both
	// divisible by 8 (64-bit aligned), so will never need padding

	// Ensure enough room for proposal
	if (len < offset + (len64 * sizeof(uint64_t)))
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	// Build proposal extension header
	struct sadb_prop *prop_ext = (struct sadb_prop*)(buff + offset);
	prop_ext->sadb_prop_len = len64;
	prop_ext->sadb_prop_exttype = SADB_EXT_PROPOSAL;
	prop_ext->sadb_prop_replay = _replay_window;
	offset += sizeof(sadb_prop);

	// Write combinations
	for (auto e = _combs.begin(); e < _combs.end(); e++)
	{
		const struct sadb_comb &entry = *e;

		memcpy(buff + offset, &entry, sizeof(sadb_comb));
		offset += sizeof(sadb_comb);
	}

	// Write size of full message
	// Note that offset has only increased in 64-bit
	// iterations, so rounding is not necessary
	hdr->sadb_msg_len = (offset / sizeof(uint64_t));

	return NO_ERROR;
}

int PFKeyV2MessageAcquire::Deserialize(uint8_t *data, size_t len)
{
	return NO_ERROR;
}

uint8_t PFKeyV2MessageAcquire::GetMessageType()
{
	return SADB_ACQUIRE;
}

const struct sockaddr& PFKeyV2MessageAcquire::GetSourceAddress(uint8_t &prefix_len, uint8_t &protocol)
{
	prefix_len = _src_prefix;
	protocol = _src_protocol;
	return reinterpret_cast<const struct sockaddr&>(_src_addr);
}

const struct sockaddr& PFKeyV2MessageAcquire::GetDestinationAddress(uint8_t &prefix_len, uint8_t &protocol)
{
	prefix_len = _dst_prefix;
	protocol = _dst_protocol;
	return reinterpret_cast<const struct sockaddr&>(_dst_addr);
}

void PFKeyV2MessageAcquire::SetSourceAddress(const struct sockaddr &addr, uint8_t prefix_len, uint8_t protocol)
{
	_src_prefix = prefix_len;
	_src_protocol = protocol;
	IPUtils::StoreSockaddr(addr, _src_addr);
}

void PFKeyV2MessageAcquire::SetDestinationAddress(const struct sockaddr &addr, uint8_t prefix_len, uint8_t protocol)
{
	_dst_prefix = prefix_len;
	_dst_protocol = protocol;
	IPUtils::StoreSockaddr(addr, _dst_addr);
}

void PFKeyV2MessageAcquire::AddProposedParameters(const struct sadb_comb &comb)
{
	_combs.push_back(comb);
}

uint32_t PFKeyV2MessageAcquire::GetReplayWindow()
{
	return _replay_window;
}

void PFKeyV2MessageAcquire::SetReplayWindow(uint32_t replay)
{
	_replay_window = replay;
}
