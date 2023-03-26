#include "keys/pf_key_v2/messages/PFKeyMessageFactory.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageAcquire.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageGet.hpp"
#include "keys/pf_key_v2/messages/PFKeyMessageUpdate.hpp"

PFKeyMessageBase* PFKeyMessageFactory::Build(const uint8_t *buff, size_t len)
{
	// Verify enough data in the buffer for the base header
	if (len < sizeof(struct sadb_msg))
	{
		return nullptr;
	}

	struct sadb_msg *hdr = (struct sadb_msg *)(buff);
	switch (hdr->sadb_msg_type)
	{
		case SADB_ACQUIRE:
		{
			return reinterpret_cast<PFKeyMessageBase*>(new PFKeyMessageAcquire());
		}
		case SADB_GET:
		{
			return reinterpret_cast<PFKeyMessageBase*>(new PFKeyMessageAcquire());
		}
		case SADB_UPDATE:
		{
			return reinterpret_cast<PFKeyMessageBase*>(new PFKeyMessageGet());
		}
		default:
		{
			return nullptr;
		}
	}
}
