#include <gtest/gtest.h>
#include "keys/pf_key_v2/extensions/PFKeyProposalExtension.hpp"
#include <cstring>
#include "logging/Logger.hpp"

TEST(test_PFKeyProposalExtension, test_Deserialize)
{
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	const size_t DATA_LEN = 224;
	uint8_t data[DATA_LEN];
	size_t offset = 0;

	// Build header
	struct sadb_prop hdr = {0};
	hdr.sadb_prop_len = (sizeof(struct sadb_prop) + (3 * sizeof(struct sadb_comb))) / sizeof(uint64_t);
	hdr.sadb_prop_exttype = SADB_EXT_PROPOSAL;
	hdr.sadb_prop_replay = 64;

	// Copy into data
	memcpy(data + offset, &hdr, sizeof(struct sadb_prop));
	offset += sizeof(struct sadb_prop);

	// Build combination 1
	struct sadb_comb comb1 = {0};
	comb1.sadb_comb_auth = SADB_AALG_SHA1HMAC;
	comb1.sadb_comb_encrypt = SADB_EALG_3DESCBC;
	comb1.sadb_comb_flags = 0;
	comb1.sadb_comb_auth_minbits = 32;
	comb1.sadb_comb_auth_maxbits = 64;
	comb1.sadb_comb_encrypt_minbits = 128;
	comb1.sadb_comb_encrypt_minbits = 256;
	comb1.sadb_comb_soft_allocations = 1;
	comb1.sadb_comb_hard_allocations = 2;
	comb1.sadb_comb_soft_bytes = 8;
	comb1.sadb_comb_hard_bytes = 16;
	comb1.sadb_comb_soft_addtime = 100;
	comb1.sadb_comb_hard_addtime = 200;
	comb1.sadb_comb_soft_usetime = 50;
	comb1.sadb_comb_hard_usetime = 75;

	// Copy into data
	memcpy(data + offset, &comb1, sizeof(struct sadb_comb));
	offset += sizeof(struct sadb_comb);

	// Build combination 2
	struct sadb_comb comb2 = {0};
	comb2.sadb_comb_auth = SADB_AALG_MD5HMAC;
	comb2.sadb_comb_encrypt = SADB_EALG_DESCBC;
	comb2.sadb_comb_flags = 0;
	comb2.sadb_comb_auth_minbits = 32;
	comb2.sadb_comb_auth_maxbits = 64;
	comb2.sadb_comb_encrypt_minbits = 128;
	comb2.sadb_comb_encrypt_minbits = 256;
	comb2.sadb_comb_soft_allocations = 1;
	comb2.sadb_comb_hard_allocations = 2;
	comb2.sadb_comb_soft_bytes = 8;
	comb2.sadb_comb_hard_bytes = 16;
	comb2.sadb_comb_soft_addtime = 100;
	comb2.sadb_comb_hard_addtime = 200;
	comb2.sadb_comb_soft_usetime = 50;
	comb2.sadb_comb_hard_usetime = 75;

	// Copy into data
	memcpy(data + offset, &comb2, sizeof(struct sadb_comb));
	offset += sizeof(struct sadb_comb);

	// Build combination 3
	struct sadb_comb comb3 = {0};
	comb3.sadb_comb_auth = SADB_AALG_NONE;
	comb3.sadb_comb_encrypt = SADB_EALG_NONE;
	comb3.sadb_comb_flags = 0;
	comb3.sadb_comb_auth_minbits = 32;
	comb3.sadb_comb_auth_maxbits = 64;
	comb3.sadb_comb_encrypt_minbits = 128;
	comb3.sadb_comb_encrypt_minbits = 256;
	comb3.sadb_comb_soft_allocations = 1;
	comb3.sadb_comb_hard_allocations = 2;
	comb3.sadb_comb_soft_bytes = 8;
	comb3.sadb_comb_hard_bytes = 16;
	comb3.sadb_comb_soft_addtime = 100;
	comb3.sadb_comb_hard_addtime = 200;
	comb3.sadb_comb_soft_usetime = 50;
	comb3.sadb_comb_hard_usetime = 75;

	// Copy into data
	memcpy(data + offset, &comb3, sizeof(struct sadb_comb));
	offset += sizeof(struct sadb_comb);

	PFKeyProposalExtension ext;
	size_t len = DATA_LEN;
	int status = ext.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_PROPOSAL, ext.GetType());
	ASSERT_EQ(64, ext.GetReplayWindow());

	struct sadb_comb *_comb1 = ext.GetCombinationAt(0);
	struct sadb_comb *_comb2 = ext.GetCombinationAt(1);
	struct sadb_comb *_comb3 = ext.GetCombinationAt(2);

	ASSERT_EQ(0, memcmp(&comb1, _comb1, sizeof(struct sadb_comb)));
	ASSERT_EQ(0, memcmp(&comb2, _comb2, sizeof(struct sadb_comb)));
	ASSERT_EQ(0, memcmp(&comb3, _comb3, sizeof(struct sadb_comb)));
}

TEST(test_PFKeyProposalExtension, test_Serialize)
{
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	const size_t DATA_LEN = 224;
	uint8_t data[DATA_LEN];
	size_t offset = 0;

	PFKeyProposalExtension ext;
	ext.SetReplayWindow(64);

	// Build combination 1
	struct sadb_comb comb1 = {0};
	comb1.sadb_comb_auth = SADB_AALG_SHA1HMAC;
	comb1.sadb_comb_encrypt = SADB_EALG_3DESCBC;
	comb1.sadb_comb_flags = 0;
	comb1.sadb_comb_auth_minbits = 32;
	comb1.sadb_comb_auth_maxbits = 64;
	comb1.sadb_comb_encrypt_minbits = 128;
	comb1.sadb_comb_encrypt_minbits = 256;
	comb1.sadb_comb_soft_allocations = 1;
	comb1.sadb_comb_hard_allocations = 2;
	comb1.sadb_comb_soft_bytes = 8;
	comb1.sadb_comb_hard_bytes = 16;
	comb1.sadb_comb_soft_addtime = 100;
	comb1.sadb_comb_hard_addtime = 200;
	comb1.sadb_comb_soft_usetime = 50;
	comb1.sadb_comb_hard_usetime = 75;

	// Build combination 2
	struct sadb_comb comb2 = {0};
	comb2.sadb_comb_auth = SADB_AALG_MD5HMAC;
	comb2.sadb_comb_encrypt = SADB_EALG_DESCBC;
	comb2.sadb_comb_flags = 0;
	comb2.sadb_comb_auth_minbits = 32;
	comb2.sadb_comb_auth_maxbits = 64;
	comb2.sadb_comb_encrypt_minbits = 128;
	comb2.sadb_comb_encrypt_minbits = 256;
	comb2.sadb_comb_soft_allocations = 1;
	comb2.sadb_comb_hard_allocations = 2;
	comb2.sadb_comb_soft_bytes = 8;
	comb2.sadb_comb_hard_bytes = 16;
	comb2.sadb_comb_soft_addtime = 100;
	comb2.sadb_comb_hard_addtime = 200;
	comb2.sadb_comb_soft_usetime = 50;
	comb2.sadb_comb_hard_usetime = 75;

	// Build combination 3
	struct sadb_comb comb3 = {0};
	comb3.sadb_comb_auth = SADB_AALG_NONE;
	comb3.sadb_comb_encrypt = SADB_EALG_NONE;
	comb3.sadb_comb_flags = 0;
	comb3.sadb_comb_auth_minbits = 32;
	comb3.sadb_comb_auth_maxbits = 64;
	comb3.sadb_comb_encrypt_minbits = 128;
	comb3.sadb_comb_encrypt_minbits = 256;
	comb3.sadb_comb_soft_allocations = 1;
	comb3.sadb_comb_hard_allocations = 2;
	comb3.sadb_comb_soft_bytes = 8;
	comb3.sadb_comb_hard_bytes = 16;
	comb3.sadb_comb_soft_addtime = 100;
	comb3.sadb_comb_hard_addtime = 200;
	comb3.sadb_comb_soft_usetime = 50;
	comb3.sadb_comb_hard_usetime = 75;

	ext.AddCombination(comb1);
	ext.AddCombination(comb2);
	ext.AddCombination(comb3);

	size_t len = DATA_LEN;
	int status = ext.Serialize(data, len);

	ASSERT_EQ(0, status);

	PFKeyProposalExtension ext2;
	status = ext2.Deserialize(data, len);

	ASSERT_EQ(0, status);

	ASSERT_EQ(DATA_LEN, ext2.GetLengthBytes());
	ASSERT_EQ(SADB_EXT_PROPOSAL, ext2.GetType());
	ASSERT_EQ(64, ext2.GetReplayWindow());

	struct sadb_comb *_comb1 = ext2.GetCombinationAt(0);
	struct sadb_comb *_comb2 = ext2.GetCombinationAt(1);
	struct sadb_comb *_comb3 = ext2.GetCombinationAt(2);

	ASSERT_EQ(0, memcmp(&comb1, _comb1, sizeof(struct sadb_comb)));
	ASSERT_EQ(0, memcmp(&comb2, _comb2, sizeof(struct sadb_comb)));
	ASSERT_EQ(0, memcmp(&comb3, _comb3, sizeof(struct sadb_comb)));


}
