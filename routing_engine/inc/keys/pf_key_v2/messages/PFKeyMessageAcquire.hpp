#ifndef INC_PFKEYMESSAGEACQUIRE_HPP_
#define INC_PFKEYMESSAGEACQUIRE_HPP_

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"
#include "keys/pf_key_v2/extensions/PFKeyAddressExtension.hpp"
#include "keys/pf_key_v2/extensions/PFKeyIdentityExtension.hpp"
#include "keys/pf_key_v2/extensions/PFKeyProposalExtension.hpp"

class PFKeyMessageAcquire : public PFKeyMessageBase
{
public:
	PFKeyMessageAcquire();
	PFKeyMessageAcquire(const PFKeyMessageAcquire &rhs);
	~PFKeyMessageAcquire() override;

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	void PrintInfo();

	uint8_t GetMessageType();
	virtual size_t GetLengthBytes();

	PFKeyAddressExtension& SourceAddress();
	PFKeyAddressExtension& DestinationAddress();
	PFKeyAddressExtension& ProxyAddress();
	PFKeyIdentityExtension& SourceID();
	PFKeyIdentityExtension& DestinationID();
	PFKeyProposalExtension& Proposal();

	void SetProxyAddressPresent(bool present);
	void SetSourceIDPresent(bool present);
	void SetDestinationIDPresent(bool present);

	bool GetProxyAddressPresent();
	bool GetSourceIDPresent();
	bool GetDestinationIDPresent();

private:
	PFKeyAddressExtension _src;
	PFKeyAddressExtension _dst;
	PFKeyAddressExtension _proxy;
	PFKeyIdentityExtension _src_id;
	PFKeyIdentityExtension _dst_id;
	PFKeyProposalExtension _proposal;

	bool _proxy_present;
	bool _src_id_present;
	bool _dst_id_present;
};

#endif
