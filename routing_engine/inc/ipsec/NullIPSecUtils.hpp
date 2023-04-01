#ifndef INC_NULLIPSECUTILS_HPP_
#define INC_NULLIPSECUTILS_HPP_

#include "ipsec/IIPSecUtils.hpp"

#include "layer3/IPv4Packet.hpp"

#include <cstdint>
#include <cstdlib>

#include "keys/IKeyManager.hpp"

class NullIPSecUtils : public IIPSecUtils
{
public:
	NullIPSecUtils();
	NullIPSecUtils(IKeyManager *key_manager);
	~NullIPSecUtils() override;

	int ValidateAuthHeader(IIPPacket *pkt);
	int TransformAuthHeader(IIPPacket *pkt);
	int ValidateAuthHeaderSeqNum(IIPPacket *pkt);
	int CalculateICV(IIPPacket *pkt, uint8_t *icv_out, size_t len);

private:
	int ValidateAuthHeaderV4(IPv4Packet *pkt);

	int CalculateICVV4(IPv4Packet *pkt, uint8_t *icv_out, size_t len);

	void _derive_gateway(const struct sockaddr &host_ip, struct sockaddr &gateway);

	const size_t SHA_256_HMAC_LEN = 32; // SHA256 HMAC digest length (256 bits)
	const size_t SHA_256_KEY_LEN = 64;

	IKeyManager *_key_manager;
};

#endif
