#include <ipsec/LocalIPSecUtils.hpp>

#include "ipsec/IPSecAuthHeader.hpp"
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "logging/Logger.hpp"

LocalIPSecUtils::LocalIPSecUtils(IKeyManager *key_manager)
{
	_key_manager = key_manager;
}

LocalIPSecUtils::~LocalIPSecUtils()
{
}

bool LocalIPSecUtils::ValidateAuthHeader(IIPPacket *pkt)
{
	switch (pkt->GetIPVersion())
	{
		case 4:
		{
			return ValidateAuthHeaderV4(reinterpret_cast<IPv4Packet*>(pkt));
		}
		case 6:
		{
			return false;
		}
		default:
		{
			return false;
		}
	}
}

bool LocalIPSecUtils::ValidateAuthHeaderV4(IPv4Packet *pkt)
{
	int status = ERROR_UNSET;
	uint8_t icv_calculated[SHA_256_HMAC_LEN];

	// Verify that this packet has an authentication header
	if (pkt->GetProtocol() != IPPROTO_AH)
	{
		Logger::Log(LOG_DEBUG, "Packet contains no authentication header");
		return false;
	}

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = pkt->GetData(ip_payload);
	status = auth_hdr.Deserialize(ip_payload, ip_payload_len_bytes);
	if (status != NO_ERROR)
	{
		Logger::Log(LOG_DEBUG, "Failed to deserialize authentication header");
		return false;
	}

	// Get the ICV contained in the authentication header
	const uint8_t *icv_received;
	size_t icv_rcv_len_bytes = auth_hdr.GetICV(icv_received);

	// Verify enough data in the received ICV
	// This will ensure that we do not overflow
	// the buffer when comparing the ICV
	if (icv_rcv_len_bytes < SHA_256_HMAC_LEN)
	{
		Logger::Log(LOG_DEBUG, "Not enough data in ICV for HMAC");
		return false;
	}

	// Process and calculate the ICV
	status = CalculateICV(pkt, icv_calculated, SHA_256_HMAC_LEN);
	if (status != NO_ERROR)
	{
		Logger::Log(LOG_DEBUG, "Failed to calculate ICV");
		return false;
	}

	std::cout << "-------- Calculated ICV --------" << std::endl;
	std::cout << Logger::BytesToString(icv_calculated, SHA_256_HMAC_LEN);
	std::cout << "--------------------------------" << std::endl;

	// Compare received ICV with calculated ICV
	bool match = (memcmp(icv_received, icv_calculated, SHA_256_HMAC_LEN) == 0);
	if (!match)
	{
		Logger::Log(LOG_SECURE, "ICV does not match");
	}

	return match;
}

int LocalIPSecUtils::CalculateICV(IIPPacket *pkt, uint8_t *icv_out, size_t len)
{
	switch (pkt->GetIPVersion())
	{
		case 4:
		{
			return CalculateICVV4(reinterpret_cast<IPv4Packet*>(pkt), icv_out, len);
		}
		case 6:
		{
			return false;
		}
		default:
		{
			return false;
		}
	}
}

int LocalIPSecUtils::CalculateICVV4(IPv4Packet *pkt, uint8_t *icv_out, size_t len)
{
	// Verify that this packet contains an authentication header
	if (pkt->GetProtocol() != IPPROTO_AH)
	{
		return IPSEC_AH_ERROR_NO_AUTH_HEADER;
	}

	// Create a scratch area which will be
	// used to store a mutable copy of
	// the data during processing
	static uint8_t scratch[2048];

	// Create a copy of the packet to modify
	IPv4Packet tmp_pkt = *pkt;

	// Zero-out mutable fields
	tmp_pkt.SetTOS(0);
	tmp_pkt.SetDontFragment(false);
	tmp_pkt.SetMoreFragments(false);
	tmp_pkt.SetFragmentOffset(false);
	tmp_pkt.SetTTL(0);

	// Serialize packet into scratch area
	uint16_t ip_pkt_len_bytes = 2048;
	int status = pkt->Serialize(scratch, ip_pkt_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Clear the IP header checksum
	*(uint16_t*)(scratch + 12) = 0;

	// Locate the authentication header
	uint8_t ip_hdr_len_bytes = tmp_pkt.GetHeaderLengthBytes();
	uint8_t *auth_hdr_data = (uint8_t*)(scratch + ip_hdr_len_bytes);

	// Deserialize the authentication header
	IPSecAuthHeader auth_hdr;
	size_t auth_hdr_len_bytes = ip_pkt_len_bytes - ip_hdr_len_bytes;
	status = auth_hdr.Deserialize(auth_hdr_data, auth_hdr_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Clear the ICV
	const uint8_t *icv_in;
	size_t icv_len_bytes = auth_hdr.GetICV(icv_in);
	if (icv_len_bytes < len)
	{
		return IPSEC_AH_ERROR_ICV_LEN_INCORRECT;
	}
	memset(icv_out, 0, len);
	auth_hdr.SetICV(icv_out, len);

	// Update authentication header in scratch area
	status = auth_hdr.Serialize(auth_hdr_data, auth_hdr_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Note: In some cases (such as ESN),
	// additional fields are appended to
	// the message. We are not supporting
	// these cases.
	size_t msg_len_bytes = ip_pkt_len_bytes;

	// Retrieve key information
	uint8_t key[SHA_256_KEY_LEN];
	size_t keylen;
	status = _key_manager->GetKey(auth_hdr.GetSPI(), key, keylen);
	if (status != 0)
	{
		return status;
	}

	// Calculate the SHA256 message digest
	uint32_t icv_len = 0;
	uint8_t *digest = HMAC(EVP_sha256(), key, (int)keylen, scratch, msg_len_bytes, icv_out, &icv_len);

	if (digest == nullptr)
	{
		return IPSEC_AH_ERROR_HMAC_FAILED;
	}

	return NO_ERROR;
}



