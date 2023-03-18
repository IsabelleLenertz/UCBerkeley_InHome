#ifndef INC_PFKEYV2MESSAGEFLUSH_HPP_
#define INC_PFKEYV2MESSAGEFLUSH_HPP_

#include "keys/pf_key_v2/PFKeyV2MessageBase.hpp"

class PFKeyV2MessageFlush : public PFKeyV2MessageBase
{
public:
	PFKeyV2MessageFlush();
	~PFKeyV2MessageFlush() override;

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	uint8_t GetMessageType();
};

#endif
