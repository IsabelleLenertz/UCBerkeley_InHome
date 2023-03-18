#include <gtest/gtest.h>
#include <arpa/inet.h>
#include "keys/pf_key_v2/extensions/PFKeyAddressExtension.hpp"

TEST(test_PFKeyAddressExtension, test_Deserialize)
{
	const size_t DATA_LEN = 24;
	const uint8_t data[DATA_LEN] = {0x03, 0x00, 0x05, 0x00, 0x06, 0x18, 0x00, 0x00,
									0x02, 0x00, 0x40, 0x1F, 0xC0, 0xA8, 0x00, 0x01,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	PFKeyAddressExtension ext;
	size_t len = DATA_LEN;
	int status = ext.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_ADDRESS_SRC, ext.GetType());

	ASSERT_EQ(true, ext.IsValid());

	ASSERT_EQ(IPPROTO_TCP, ext.GetProtocol());
	ASSERT_EQ(24, ext.GetPrefixLength());

	sockaddr_in exp_addr;
	inet_pton(AF_INET, "192.168.0.1", &exp_addr.sin_addr);
	exp_addr.sin_family = AF_INET;
	exp_addr.sin_port = 8000;
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(reinterpret_cast<const sockaddr&>(exp_addr), ext.GetAddress()));
}

TEST(test_PFKeyAddressExtension, test_Serialize)
{
	const size_t DATA_LEN = 24;
	uint8_t data[DATA_LEN];

	PFKeyAddressExtension ext;
	ext.SetTypeSource();
	ext.SetProtocol(IPPROTO_TCP);
	ext.SetPrefixLength(24);

	sockaddr_in src_addr;
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = 8000;
	inet_pton(AF_INET, "192.168.0.1", &src_addr.sin_addr);
	ext.SetAddress(reinterpret_cast<sockaddr&>(src_addr));

	size_t len = DATA_LEN;
	int status = ext.Serialize(data, len);
	ASSERT_EQ(0, status);
	ASSERT_EQ(DATA_LEN, len);

	PFKeyAddressExtension ext2;
	status = ext2.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext2.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_ADDRESS_SRC, ext2.GetType());

	ASSERT_EQ(true, ext2.IsValid());

	ASSERT_EQ(IPPROTO_TCP, ext2.GetProtocol());
	ASSERT_EQ(24, ext2.GetPrefixLength());

	sockaddr_in exp_addr;
	inet_pton(AF_INET, "192.168.0.1", &exp_addr.sin_addr);
	exp_addr.sin_family = AF_INET;
	exp_addr.sin_port = 8000;
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(reinterpret_cast<const sockaddr&>(exp_addr), ext2.GetAddress()));
}
