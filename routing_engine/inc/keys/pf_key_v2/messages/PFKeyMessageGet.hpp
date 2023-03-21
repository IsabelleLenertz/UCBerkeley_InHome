#ifndef INC_PFKEYMESSAGEGET_HPP_
#define INC_PFKEYMESSAGEGET_HPP_

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"
#include "keys/pf_key_v2/extensions/PFKeyAssociationExtension.hpp"
#include "keys/pf_key_v2/extensions/PFKeyAddressExtension.hpp"
#include "keys/pf_key_v2/extensions/PFKeyKeyExtension.hpp"
#include "keys/pf_key_v2/extensions/PFKeyIdentityExtension.hpp"

class PFKeyMessageGet : public PFKeyMessageBase
{
public:
	PFKeyMessageGet();
	~PFKeyMessageGet() override;

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	uint8_t GetMessageType();
	virtual size_t GetLengthBytes();

	PFKeyAssociationExtension* Association();
	PFKeyAddressExtension* SourceAddress();
	PFKeyAddressExtension* DestinationAddress();
	PFKeyAddressExtension* ProxyAddress();
	PFKeyKeyExtension* AuthKey();
	PFKeyKeyExtension* EncryptKey();
	PFKeyIdentityExtension* SourceID();
	PFKeyIdentityExtension* DestinationID();

	void SetProxyAddressPresent(bool present);
	void SetAuthKeyPresent(bool present);
	void SetEncryptKeyPresent(bool present);
	void SetSourceIDPresent(bool present);
	void SetDestinationIDPresent(bool present);

private:
	PFKeyAssociationExtension _assoc;
	PFKeyAddressExtension _src;
	PFKeyAddressExtension _dst;
	PFKeyAddressExtension _proxy;
	PFKeyKeyExtension _auth_key;
	PFKeyKeyExtension _encrypt_key;
	PFKeyIdentityExtension _src_id;
	PFKeyIdentityExtension _dst_id;

	bool _proxy_present;
	bool _auth_key_present;
	bool _encrypt_key_present;
	bool _src_id_present;
	bool _dst_id_present;
};

#endif
