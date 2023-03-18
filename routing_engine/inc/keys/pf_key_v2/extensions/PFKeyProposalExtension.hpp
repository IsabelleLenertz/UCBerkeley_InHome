#ifndef INC_PFKEYPROPOSALEXTENSION_HPP_
#define INC_PFKEYPROPOSALEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"

class PFKeyProposalExtension : public IPFKeyExtension
{
public:
	PFKeyProposalExtension();
	~PFKeyProposalExtension() override;

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(const uint8_t *data, size_t &len);

	size_t GetLengthBytes();

	uint16_t GetType();

	bool IsValid();
}



#endif
