#ifndef INC_PFKEYADDRESSEXTENSION_HPP_
#define INC_PFKEYADDRESSEXTENSION_HPP_

#include "keys/pf_key_v2/extensions/IPFKeyExtension.hpp"
#include "layer3/IPUtils.hpp"

class PFKeyAddressExtension : public IPFKeyExtension
{
public:
	PFKeyAddressExtension();
	~PFKeyAddressExtension() override;

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(const uint8_t *data, size_t &len);

	size_t GetLengthBytes();

	uint16_t GetType();

	bool IsValid();

	/// <summary>
	/// Sets address extension as a source address
	/// </summary>
	void SetTypeSource();

	/// <summary>
	/// Sets address extension as a destination address
	/// </summary>
	void SetTypeDestination();

	/// <summary>
	/// Sets address extension as a proxy address
	/// </summary>
	void SetTypeProxy();

	/// <summary>
	/// Gets the socket address for this address extension
	/// </summary>
	/// <returns>Reference to socket address</returns>
	const struct sockaddr &GetAddress();

	/// <summary>
	/// Sets the socket address for this address extension
	/// </summary>
	/// <param name="addr">Socket address</param>
	void SetAddress(const struct sockaddr &addr);

	/// <summary>
	/// Gets the prefix length for this address extension
	/// </summary>
	/// <returns>Prefix length</returns>
	uint8_t GetPrefixLength();

	/// <summary>
	/// Sets the prefix length for this address extension
	/// </summary>
	/// <param name="prefix_len">Prefix length</param>
	void SetPrefixLength(uint8_t prefix_len);

	/// <summary>
	/// Gets the protocol number for this address extension
	/// </summary>
	/// <returns>Protocol number</returns>
	uint8_t GetProtocol();

	/// <summary>
	/// Sets the protocol number for this address extension
	/// </summary>
	/// <param name="protocol">Protocol number</param>
	void SetProtocol(uint8_t protocol);

private:
	struct sockaddr_storage _addr;
	uint16_t _type;
	uint8_t _prefix_len;
	uint8_t _protocol;
};

#endif
