#include <gtest/gtest.h>
#include "ipsec/IPSecAuthHeader.hpp"
#include <arpa/inet.h>
#include <cstring>

TEST(test_IPSecAuthHeader, test_Deserialize)
{
	const size_t DATA_LEN = 16;
	const uint8_t data[DATA_LEN] = {0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                    0x00, 0x00, 0x02, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};

	IPSecAuthHeader hdr;
	size_t len = DATA_LEN;
	int status = hdr.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(IPPROTO_TCP, hdr.GetNextHeader());
	ASSERT_EQ(DATA_LEN, hdr.GetLengthBytes());
	ASSERT_EQ(256, hdr.GetSPI());
	ASSERT_EQ(512, hdr.GetSequenceNumber());

	const uint8_t *icv_data;
	size_t icv_len_bytes = hdr.GetICV(icv_data);

	// Verify ICV data
	ASSERT_EQ(0, memcmp(data + 12, icv_data, icv_len_bytes));
}

TEST(test_IPSecAuthHeader, test_Serialize)
{
	const size_t DATA_LEN = 16;
	uint8_t data[DATA_LEN];

	const size_t ICV_LEN = 4;
	const uint8_t icv[ICV_LEN] = {0xAA, 0xBB, 0xCC, 0xDD};

	IPSecAuthHeader hdr;
	hdr.SetNextHeader(IPPROTO_TCP);
	hdr.SetSPI(256);
	hdr.SetSequenceNumber(512);
	hdr.SetICV(icv, ICV_LEN);

	size_t len = DATA_LEN;
	int status = hdr.Serialize(data, len);

	ASSERT_EQ(0, status);

	IPSecAuthHeader hdr2;
	status = hdr2.Deserialize(data, len);
	ASSERT_EQ(0, status);

	ASSERT_EQ(IPPROTO_TCP, hdr2.GetNextHeader());
	ASSERT_EQ(DATA_LEN, hdr2.GetLengthBytes());
	ASSERT_EQ(256, hdr2.GetSPI());
	ASSERT_EQ(512, hdr2.GetSequenceNumber());

	const uint8_t *icv_data;
	size_t icv_len_bytes = hdr2.GetICV(icv_data);

	// Verify ICV data
	ASSERT_EQ(0, memcmp(data + 12, icv_data, icv_len_bytes));
}
