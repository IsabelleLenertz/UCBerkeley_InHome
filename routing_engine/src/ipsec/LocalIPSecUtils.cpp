#include <ipsec/LocalIPSecUtils.hpp>

#include "layer3/IPPacketFactory.hpp"
#include "layer3/IPUtils.hpp"
#include "ipsec/IPSecAuthHeader.hpp"
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "logging/Logger.hpp"

#define ONE_WAY_AUTH

LocalIPSecUtils::LocalIPSecUtils(IKeyManager *key_manager)
{
	_key_manager = key_manager;
}

LocalIPSecUtils::~LocalIPSecUtils()
{
}

int LocalIPSecUtils::ValidateAuthHeader(IIPPacket *pkt)
{
	switch (pkt->GetIPVersion())
	{
		case 4:
		{
			return ValidateAuthHeaderV4(reinterpret_cast<IPv4Packet*>(pkt));
		}
		case 6:
		{
			return IPSEC_ERROR_UNSUPPORTED_PROTOCOL;
		}
		default:
		{
			return IPSEC_ERROR_UNSUPPORTED_PROTOCOL;
		}
	}
}

int LocalIPSecUtils::ValidateAuthHeaderV4(IPv4Packet *pkt)
{
	std::stringstream sstream;
	int status = ERROR_UNSET;
	uint8_t icv_calculated[SHA_256_HMAC_LEN];

	// Verify that this packet has an authentication header
	if (pkt->GetProtocol() != IPPROTO_AH)
	{
		return IPSEC_AH_ERROR_NO_AUTH_HEADER;
	}

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = pkt->GetData(ip_payload);
	status = auth_hdr.Deserialize(ip_payload, ip_payload_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Get the ICV contained in the authentication header
	const uint8_t *icv_received;
	size_t icv_rcv_len_bytes = auth_hdr.GetICV(icv_received);

	// Verify enough data in the received ICV
	// This will ensure that we do not overflow
	// the buffer when comparing the ICV
	if (icv_rcv_len_bytes < SHA_256_HMAC_LEN)
	{
		return IPSEC_AH_ERROR_ICV_LEN_INCORRECT;
	}

	// Process and calculate the ICV
	status = CalculateICV(pkt, icv_calculated, SHA_256_HMAC_LEN);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Compare received ICV with calculated ICV
	bool match = (memcmp(icv_received, icv_calculated, SHA_256_HMAC_LEN) == 0);
	if (!match)
	{
		return IPSEC_AH_ERROR_INCORRECT_ICV;
	}

	return NO_ERROR;
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
			return IPSEC_ERROR_UNSUPPORTED_PROTOCOL;
		}
		default:
		{
			return IPSEC_ERROR_UNSUPPORTED_PROTOCOL;
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

	// Calculate the SHA256 message digest
	uint32_t icv_len = 0;
	uint8_t *digest = HMAC(EVP_sha256(), key, keylen, scratch, msg_len_bytes, icv_out, &icv_len);

	if (digest == nullptr)
	{
		return IPSEC_AH_ERROR_HMAC_FAILED;
	}

	return NO_ERROR;
}

int LocalIPSecUtils::TransformAuthHeader(IIPPacket *pkt)
{
	int status = ERROR_UNSET;

#ifndef ONE_WAY_AUTH
	// Verify that this packet has an authentication header
	if (pkt->GetProtocol() != IPPROTO_AH)
	{
		return IPSEC_AH_ERROR_NO_AUTH_HEADER;
	}

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = pkt->GetData(ip_payload);
	size_t auth_hdr_len_bytes = ip_payload_len_bytes;
	status = auth_hdr.Deserialize(ip_payload, auth_hdr_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Update the source/destination address in the outer packet
	// Deserialize inner IP packet
	const uint8_t *auth_hdr_payload = (uint8_t*)(ip_payload + auth_hdr_len_bytes);
	size_t auth_hdr_payload_len_bytes = ip_payload_len_bytes - auth_hdr_len_bytes;
	IIPPacket *inner_pkt = IPPacketFactory::BuildPacket(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (inner_pkt == nullptr)
	{
		return IPV4_ERROR_INVALID_VERSION;
	}

	status = inner_pkt->Deserialize(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (status != NO_ERROR)
	{
		return status;
	}

	// Get the destination of the outer packet to the destination of the inner packet
	pkt->SetDestinationAddress(inner_pkt->GetDestinationAddress());
	// Derive the gateway and set source address
	struct sockaddr_storage gateway;
	struct sockaddr &_gateway = reinterpret_cast<struct sockaddr&>(gateway);
	_derive_gateway(inner_pkt->GetDestinationAddress(), _gateway);
	pkt->SetSourceAddress(_gateway);

	uint32_t spi;
	status = _key_manager->GetSPI(pkt->GetSourceAddress(), pkt->GetDestinationAddress(), spi);
	auth_hdr.SetSPI(spi);

	if (status != NO_ERROR)
	{
		return status;
	}

	// Get the replay context
	uint32_t replay_right;
	uint32_t replay_map;
	status = _key_manager->GetReplayContext(auth_hdr.GetSPI(), pkt->GetSourceAddress(), pkt->GetDestinationAddress(), replay_right, replay_map);

	if (status != NO_ERROR)
	{
		return status;
	}

	// Set sequence number and update replay context
	uint32_t seq_num = replay_right;
	// If right side of window is less than or equal to 32,
	// then the MSB of the window may not be 1
	if (replay_right <= 32)
	{
		// Shift until a 1 bit is found, or sequence number is zero
		while ((replay_map & 0x80000000u) == 0)
		{
			replay_map <<= 1;
			seq_num--;
			if (seq_num == 0)
			{
				break;
			}
		}
	}
	seq_num++;

	auth_hdr.SetSequenceNumber(seq_num);
	status = _key_manager->MarkSequenceNumber(spi, pkt->GetSourceAddress(), pkt->GetDestinationAddress(), seq_num);

	// Reserialize the IP payload
	uint8_t buff[ip_payload_len_bytes];
	memcpy(buff, ip_payload, ip_payload_len_bytes); // Copy full IP payload into mutable buffer
	auth_hdr_len_bytes = ip_payload_len_bytes;
	// Serialize the buffer
	status = auth_hdr.Serialize(buff, auth_hdr_len_bytes);

	if (status != NO_ERROR)
	{
		return status;
	}

	// Insert updated payload
	pkt->SetData(buff, ip_payload_len_bytes);

	// Calculate ICV
	uint8_t icv_calculated[SHA_256_HMAC_LEN];
	memset(icv_calculated, 0, sizeof(icv_calculated));
	auth_hdr.SetICV(icv_calculated, SHA_256_HMAC_LEN);

	status = CalculateICV(pkt, icv_calculated, SHA_256_HMAC_LEN);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Set ICV
	auth_hdr.SetICV(icv_calculated, SHA_256_HMAC_LEN);

#else // ONE_WAY_AUTH

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = pkt->GetData(ip_payload);
	size_t auth_hdr_len_bytes = ip_payload_len_bytes;
	status = auth_hdr.Deserialize(ip_payload, auth_hdr_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Update the source/destination address in the outer packet
	// Deserialize inner IP packet
	const uint8_t *auth_hdr_payload = (uint8_t*)(ip_payload + auth_hdr_len_bytes);
	size_t auth_hdr_payload_len_bytes = ip_payload_len_bytes - auth_hdr_len_bytes;
	IIPPacket *inner_pkt = IPPacketFactory::BuildPacket(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (inner_pkt == nullptr)
	{
		return IPV4_ERROR_INVALID_VERSION;
	}

	status = inner_pkt->Deserialize(auth_hdr_payload, auth_hdr_payload_len_bytes);

	if (status != NO_ERROR)
	{
		return status;
	}

	pkt->SetSourceAddress(inner_pkt->GetSourceAddress());
	pkt->SetDestinationAddress(inner_pkt->GetDestinationAddress());
	pkt->SetProtocol(inner_pkt->GetProtocol());

	const uint8_t *inner_ip_payload;
	size_t inner_ip_payload_len_bytes = inner_pkt->GetData(inner_ip_payload);

	pkt->SetData(inner_ip_payload, inner_ip_payload_len_bytes);

#endif

	return NO_ERROR;
}

int LocalIPSecUtils::ValidateAuthHeaderSeqNum(IIPPacket *pkt)
{
	std::stringstream sstream;
	int status = ERROR_UNSET;

	// Verify that this packet has an authentication header
	if (pkt->GetProtocol() != IPPROTO_AH)
	{
		return IPSEC_AH_ERROR_NO_AUTH_HEADER;
	}

	// Get the authentication header
	IPSecAuthHeader auth_hdr;
	const uint8_t *ip_payload;
	size_t ip_payload_len_bytes = pkt->GetData(ip_payload);
	status = auth_hdr.Deserialize(ip_payload, ip_payload_len_bytes);
	if (status != NO_ERROR)
	{
		return status;
	}

	// Get the replay context
	uint32_t replay_right;
	uint32_t replay_map;
	status = _key_manager->GetReplayContext(auth_hdr.GetSPI(), pkt->GetSourceAddress(), pkt->GetDestinationAddress(), replay_right, replay_map);

	if (status != NO_ERROR)
	{
		Logger::Log(LOG_ERROR, "Failed to get reaplay context");
		return status;
	}

	// Verify that the sequence number is within the window
	uint32_t seq_num = auth_hdr.GetSequenceNumber();
	if (seq_num < replay_right - 31)
	{
		return IPSEC_AH_ERROR_INVALID_SEQ_NUM;
	}

	// Verify that the sequence number has not already been used
	if (seq_num <= replay_right)
	{
		int shift_count = replay_right - seq_num;
		uint32_t marker = 0x80000000;
		marker >= shift_count;

		if (replay_map & marker != 0)
		{
			return IPSEC_AH_ERROR_INVALID_SEQ_NUM;
		}
	}

	_key_manager->MarkSequenceNumber(auth_hdr.GetSPI(), pkt->GetSourceAddress(), pkt->GetDestinationAddress(), auth_hdr.GetSequenceNumber());

	return NO_ERROR;
}

void LocalIPSecUtils::_derive_gateway(const struct sockaddr &host_ip, struct sockaddr &gateway)
{
	struct sockaddr_storage netmask;
	switch (host_ip.sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in &_netmask = reinterpret_cast<struct sockaddr_in&>(netmask);
			_netmask.sin_family = AF_INET;
			_netmask.sin_port = 0;
			inet_pton(AF_INET, "255.255.255.252", &_netmask.sin_addr);
			break;
		}
		case AF_INET6:
		{
			// No implemented
			return;
		}
		default:
		{
			return;
		}
	}

	IPUtils::GetFirstHostIP(host_ip, reinterpret_cast<struct sockaddr&>(netmask), gateway);
}
