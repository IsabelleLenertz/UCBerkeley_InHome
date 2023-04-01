#include <gtest/gtest.h>
#include "keys/pf_key_v2/extensions/PFKeyKeyExtension.hpp"

TEST(test_PFKeyKeyExtension, test_Deserialize)
{
	const size_t DATA_LEN = 24;
	const uint8_t data[DATA_LEN] = {0x03, 0x00, 0x08, 0x00, 0x60, 0x00, 0x00, 0x00,
			                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
									0x09, 0x0A, 0x0B, 0x0C, 0x00, 0x00, 0x00, 0x00};

	PFKeyKeyExtension ext;

	size_t len = DATA_LEN;
	int status = ext.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_KEY_AUTH, ext.GetType());

	ASSERT_EQ(true, ext.IsValid());

	ASSERT_EQ(96, ext.GetNumKeyBits());

	const uint8_t *data_out;
	size_t data_out_len;
	data_out_len = ext.GetKeyData(data_out);

	ASSERT_EQ(12, data_out_len);
	ASSERT_EQ(0, memcmp(data + sizeof(struct sadb_key), data_out, data_out_len));
}

TEST(test_PFKeyKeyExtension, test_Serialize)
{
	const size_t DATA_LEN = 24;
	uint8_t data[DATA_LEN];

	const size_t KEY_LEN = 12;
	const uint8_t key_data[KEY_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			                           0x09, 0x0A, 0x0B, 0x0C};

	PFKeyKeyExtension ext;
	ext.SetKeyData(key_data, KEY_LEN, 96);
	ext.SetTypeAuth();

	size_t len = DATA_LEN;
	int status = ext.Serialize(data, len);
	ASSERT_EQ(0, status);

	PFKeyKeyExtension ext2;
	status = ext2.Deserialize(data, len);
	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext2.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_KEY_AUTH, ext2.GetType());

	ASSERT_EQ(true, ext2.IsValid());

	ASSERT_EQ(96, ext2.GetNumKeyBits());

	const uint8_t *data_out;
	size_t data_out_len;
	data_out_len = ext2.GetKeyData(data_out);

	ASSERT_EQ(12, data_out_len);
	ASSERT_EQ(0, memcmp(data + sizeof(struct sadb_key), data_out, data_out_len));

}











