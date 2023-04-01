#include <gtest/gtest.h>
#include "keys/pf_key_v2/extensions/PFKeyAssociationExtension.hpp"
#include <cstring>

#include "logging/Logger.hpp"

TEST(test_PFKeyAssociationExtension, test_Deserialize)
{
	const size_t DATA_LEN = 16;
	const uint8_t data[DATA_LEN] = {0x02, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
                                    0x40, 0x01, 0x03, 0x02, 0x00, 0x01, 0x00, 0x00};

	PFKeyAssociationExtension ext;
	size_t len = DATA_LEN;
	int status = ext.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_SA, ext.GetType());
	ASSERT_EQ(512, ext.GetSPI());
	ASSERT_EQ(64, ext.GetReplayWindow());
	ASSERT_EQ(SADB_SASTATE_MATURE, ext.GetState());
	ASSERT_EQ(SADB_AALG_SHA1HMAC, ext.GetAuthAlgorithm());
	ASSERT_EQ(SADB_EALG_DESCBC, ext.GetEncryptAlgorithm());
	ASSERT_EQ(256, ext.GetFlags());
}

TEST(test_PFKeyAssociationExtension, test_Serialize)
{
	const size_t DATA_LEN = 16;
	uint8_t data[DATA_LEN];

	PFKeyAssociationExtension ext;
	ext.SetSPI(512);
	ext.SetReplayWindow(64);
	ext.SetState(SADB_SASTATE_MATURE);
	ext.SetAuthAlgorithm(SADB_AALG_SHA1HMAC);
	ext.SetEncryptAlgorithm(SADB_EALG_DESCBC);
	ext.SetFlags(256);

	size_t len = DATA_LEN;
	int status = ext.Serialize(data, len);

	ASSERT_EQ(0, status);

	PFKeyAssociationExtension ext2;
	status = ext2.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext2.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_SA, ext2.GetType());
	ASSERT_EQ(512, ext2.GetSPI());
	ASSERT_EQ(64, ext2.GetReplayWindow());
	ASSERT_EQ(SADB_SASTATE_MATURE, ext2.GetState());
	ASSERT_EQ(SADB_AALG_SHA1HMAC, ext2.GetAuthAlgorithm());
	ASSERT_EQ(SADB_EALG_DESCBC, ext2.GetEncryptAlgorithm());
	ASSERT_EQ(256, ext.GetFlags());
}
