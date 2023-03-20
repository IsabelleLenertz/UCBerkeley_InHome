#ifndef INC_IPSECUTILS_HPP_
#define INC_IPSECUTILS_HPP_

#include "ipsec/IIPSecUtils.hpp"

#include "layer3/IPv4Packet.hpp"

#include <cstdint>
#include <cstdlib>

#include "keys/IKeyManager.hpp"

class LocalIPSecUtils
{
public:
	LocalIPSecUtils(IKeyManager *key_manager);
	~LocalIPSecUtils();

	/// <summary>
	/// Validates the Integrity Check Value (ICV)
	/// contained in an IP packet with an authentication
	/// header
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <returns>True if valid, false otherwise</returns>
	bool ValidateAuthHeader(IIPPacket *pkt);

	/// <summary>
	/// Calculates the value of the ICV
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <param name="icv_out">ICV data out</param>
	/// <param name="len">Length of ICV data</param>
	/// <returns>Error code</returns>
	int CalculateICV(IIPPacket *pkt, uint8_t *icv_out, size_t len);

private:
	bool ValidateAuthHeaderV4(IPv4Packet *pkt);

	int CalculateICVV4(IPv4Packet *pkt, uint8_t *icv_out, size_t len);

	const size_t SHA_256_HMAC_LEN = 32; // SHA256 HMAC digest length (256 bits)
	const size_t SHA_256_KEY_LEN = 64;

	IKeyManager *_key_manager;
};

#endif
