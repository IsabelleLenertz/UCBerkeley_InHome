#include <gtest/gtest.h>
#include "ipsec/LocalIPSecUtils.hpp"
#include "ipsec/IPSecAuthHeader.hpp"
#include "keys/LocalKeyManager.hpp"
#include "layer3/IPv4Packet.hpp"
#include "layer4/TCPSegment.hpp"

#include <cstring>
#include <arpa/inet.h>

#include "logging/Logger.hpp"

TEST(test_LocalIPSecUtils, test_ValidateAuthHeader)
{
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	int status;
	LocalKeyManager key_manager;
	LocalIPSecUtils ipsec_utils(&key_manager);

	const uint32_t SPI = 100;

	// Device 1 address
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 0;
	inet_pton(AF_INET, "192.168.0.1", &addr1.sin_addr);
	struct sockaddr &_addr1 = reinterpret_cast<struct sockaddr&>(addr1);

	// Device 2 address
	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 0;
	inet_pton(AF_INET, "192.168.0.1", &addr2.sin_addr);
	struct sockaddr &_addr2 = reinterpret_cast<struct sockaddr&>(addr2);

	const size_t KEY_LEN = 64;
	uint8_t key[KEY_LEN];
	for (int i = 0; i < KEY_LEN; i++)
	{
		key[i] = (uint8_t)(i % 256);
	}

	// Add the key to the key management database
	key_manager.AddKey(SPI, _addr1, _addr2, key, KEY_LEN);

	// Build TCP segment (payload)
	TCPSegment seg;
	seg.SetSourcePort(8000);
	seg.SetDestinationPort(8001);

	// Build authentication header
	IPSecAuthHeader auth_hdr;
	auth_hdr.SetNextHeader(IPPROTO_TCP);
	auth_hdr.SetSPI(SPI);
	auth_hdr.SetSequenceNumber(1024);
	uint8_t icv[32] = {
			0xd9, 0x07, 0xd7, 0xa3, 0x15, 0xb0, 0x49, 0xfb,
			0x84, 0x7a, 0x96, 0xcf, 0xf2, 0xba, 0x50, 0xcc,
			0x47, 0x8c, 0xaf, 0xe5, 0x41, 0xda, 0x17, 0x95,
			0xbd, 0x25, 0x7a, 0xf5, 0xd1, 0xae, 0xb1, 0xa4
	};
	auth_hdr.SetICV(icv, 32);

	// Serialize IP payload
	uint8_t buffer[1024];
	size_t len = 1024;
	size_t offset = 0;

	// Serialize authentication header
	status = auth_hdr.Serialize(buffer, len);
	ASSERT_EQ(0, status);

	// Advance offset and reduce length by offset
	offset += len;
	len = 1024 - offset;

	// Serialize TCP segment
	status = seg.Serialize(buffer + offset, len);
	ASSERT_EQ(0, status);

	// Advance offset
	offset += len;
	len = 1024 - offset;

	// Build IP packet
	IPv4Packet pkt;
	pkt.SetTOS(0);
	pkt.SetStreamID(1000);
	pkt.SetDontFragment(true);
	pkt.SetMoreFragments(false);
	pkt.SetFragmentOffset(0);
	pkt.SetTTL(16);
	pkt.SetProtocol(IPPROTO_AH);
	pkt.SetData(buffer, offset);

	// Serialize IP packet
	uint16_t ip_len = 1024;
	status = pkt.Serialize(buffer, ip_len);

	ASSERT_EQ(0, status);

	std::cout << "-------- IP Packet --------" << std::endl;
	std::cout << Logger::BytesToString(buffer, ip_len);
	std::cout << "---------------------------" << std::endl;

	int result = ipsec_utils.ValidateAuthHeader(reinterpret_cast<IIPPacket*>(&pkt));
	ASSERT_EQ(0, result);
}
