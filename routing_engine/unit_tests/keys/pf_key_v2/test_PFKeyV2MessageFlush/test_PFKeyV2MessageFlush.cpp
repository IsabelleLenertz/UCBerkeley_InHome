#include <gtest/gtest.h>
#include "keys/pf_key_v2/PFKeyV2MessageFlush.hpp"
#include <cstdlib>

TEST(test_PFKeyV2MessageFlush, test_Deserialize)
{
	const size_t DATA_LEN = sizeof(sadb_msg);
	const uint8_t data[DATA_LEN] = {PF_KEY_V2, SADB_FLUSH, 0x00, SADB_SATYPE_AH, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00};

	PFKeyV2MessageFlush flush;
	int status = flush.Deserialize(data, DATA_LEN);
	
	ASSERT_EQ(0, status);
	
	ASSERT_EQ(SADB_FLUSH, flush.GetMessageType());
	ASSERT_EQ(0, flush.GetErrorCode());
	ASSERT_EQ(SADB_SATYPE_AH, flush.GetSAType());
	ASSERT_EQ(256, flush.GetSequenceNumber());
	ASSERT_EQ(512, flush.GetPID());
}

TEST(test_PFKeyV2MessageFlush, test_Serialize)
{
	const size_t DATA_LEN = sizeof(sadb_msg);
	uint8_t data[DATA_LEN];
	
	PFKeyV2MessageFlush flush;
	
	flush.SetSAType(SADB_SATYPE_AH);
	flush.SetSequenceNumber(256);
	flush.SetPID(512);
	
	size_t len = DATA_LEN;
	int status = flush.Serialize(data, len);
	
	ASSERT_EQ(0, status);
	
	PFKeyV2MessageFlush flush2;
	status = flush2.Deserialize(data, len);
	
	ASSERT_EQ(0, status);
	
	ASSERT_EQ(SADB_FLUSH, flush2.GetMessageType());
	ASSERT_EQ(0, flush2.GetErrorCode());
	ASSERT_EQ(SADB_SATYPE_AH, flush2.GetSAType());
	ASSERT_EQ(256, flush2.GetSequenceNumber());
	ASSERT_EQ(512, flush2.GetPID());
}
