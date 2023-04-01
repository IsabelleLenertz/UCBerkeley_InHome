#include <gtest/gtest.h>
#include "keys/pf_key_v2/extensions/PFKeyIdentityExtension.hpp"
#include <cstring>
#include "logging/Logger.hpp"

TEST(test_PFKeyIdentityExtension, test_Deserialize)
{
	const size_t DATA_LEN = 32;
	uint8_t data[DATA_LEN] = {0x04, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00,
                              0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	// Copy ID prefix into data
	strcpy((char*)(data + 16), "192.168.1.0/24");

	PFKeyIdentityExtension ext;
	size_t len = DATA_LEN;
	int status = ext.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_IDENTITY_SRC, ext.GetType());
	ASSERT_EQ(512, ext.GetIDNumber());
	ASSERT_EQ(SADB_IDENTTYPE_PREFIX, ext.GetIDType());
	ASSERT_EQ(0, strcmp("192.168.1.0/24", ext.GetIDString()));
}

TEST(test_PFKeyIdentityExtension, test_Serialize)
{
	const size_t DATA_LEN = 32;
	uint8_t data[DATA_LEN];

	PFKeyIdentityExtension ext;
	ext.SetTypeSource();
	ext.SetIDType(SADB_IDENTTYPE_PREFIX);
	ext.SetIDNumber(512);
	ext.SetIDString("192.168.1.0/24");

	size_t len = DATA_LEN;
	int status = ext.Serialize(data, len);

	ASSERT_EQ(0, status);

	PFKeyIdentityExtension ext2;
	status = ext2.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext2.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_IDENTITY_SRC, ext2.GetType());
	ASSERT_EQ(512, ext2.GetIDNumber());
	ASSERT_EQ(SADB_IDENTTYPE_PREFIX, ext2.GetIDType());
	ASSERT_EQ(0, strcmp("192.168.1.0/24", ext2.GetIDString()));
}
