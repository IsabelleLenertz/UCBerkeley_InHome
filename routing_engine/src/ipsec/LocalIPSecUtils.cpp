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
	Logger::Log(LOG_DEBUG, "!");
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
	std::stringstream sstream;
	int status = ERROR_UNSET;
	uint8_t icv_calculated[SHA_256_HMAC_LEN];

	Logger::Log(LOG_DEBUG, "Attempting to authenticate IPv4 packet");

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
		sstream.str("");
		sstream << "Not enough data in ICV for HMAC (" << icv_rcv_len_bytes << ")";
		Logger::Log(LOG_DEBUG, sstream.str());
		return false;
	}

	// Process and calculate the ICV
	status = CalculateICV(pkt, icv_calculated, SHA_256_HMAC_LEN);
	if (status != NO_ERROR)
	{
		Logger::Log(LOG_DEBUG, "Failed to calculate ICV");
		return false;
	}

	sstream << std::endl;
	sstream << "-------- Calculated ICV --------" << std::endl;
	sstream << Logger::BytesToString(icv_calculated, SHA_256_HMAC_LEN);
	sstream  << "--------------------------------" << std::endl;
	Logger::Log(LOG_DEBUG, sstream.str());

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
	std::stringstream sstream;
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
	int status = tmp_pkt.Serialize(scratch, ip_pkt_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Clear the IP header checksum
	*(uint16_t*)(scratch + 10) = 0;

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
	status = _key_manager->GetKey(auth_hdr.GetSPI(), pkt->GetSourceAddress(), pkt->GetDestinationAddress(), key, keylen);
	if (status != 0)
	{
		return status;
	}

	sstream.str("");
	sstream << std::endl;
	sstream << "---------------- Key Data ----------------" << std::endl;
	sstream << Logger::BytesToString(key, keylen) << std::endl;
	sstream << "------------------------------------------";
	Logger::Log(LOG_DEBUG, sstream.str());

	sstream.str("");
	sstream << std::endl;
	sstream << "---------------- Scratch Data ----------------" << std::endl;
	sstream << Logger::BytesToString(scratch, msg_len_bytes) << std::endl;
	sstream << "----------------------------------------------";
	Logger::Log(LOG_DEBUG, sstream.str());

	// Calculate the SHA256 message digest
	uint32_t icv_len = 0;
	uint8_t *digest = HMAC(EVP_sha256(), key, keylen, scratch, msg_len_bytes, icv_out, &icv_len);

	sstream.str("");
	sstream << std::endl;
	sstream << "---------------- ICV ----------------" << std::endl;
	sstream << Logger::BytesToString(icv_out, icv_len) << std::endl;
	sstream << "-------------------------------------" << std::endl;
	Logger::Log(LOG_DEBUG, sstream.str());

	if (digest == nullptr)
	{
		return IPSEC_AH_ERROR_HMAC_FAILED;
	}

	return NO_ERROR;
}



