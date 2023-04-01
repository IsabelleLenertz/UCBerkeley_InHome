#include <gtest/gtest.h>
#include "keys/pf_key_v2/messages/PFKeyMessageAcquire.hpp"
#include <arpa/inet.h>
#include "logging/Logger.hpp"
#include <cstring>

TEST(test_PFKeyMessageAcquire, test_Deserialize)
{
	std::stringstream sstream;
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	int status;
	struct sockaddr_in ip;
	ip.sin_family = AF_INET;
	ip.sin_port = 0;

	// Begin by initializing extension objects
	PFKeyAddressExtension src;
	PFKeyAddressExtension dst;
	PFKeyAddressExtension proxy;
	PFKeyIdentityExtension src_id;
	PFKeyProposalExtension proposal;

	// Source Address (Gateway)
	inet_pton(AF_INET, "192.168.0.1", &ip.sin_addr);
	src.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	src.SetPrefixLength(32);
	src.SetProtocol(0);
	src.SetTypeSource();

	// Destination Address (Host IP)
	inet_pton(AF_INET, "192.168.0.2", &ip.sin_addr);
	dst.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	dst.SetPrefixLength(32);
	dst.SetProtocol(0);
	dst.SetTypeDestination();

	// Proxy Address (Private Subnet)
	inet_pton(AF_INET, "192.168.0.0", &ip.sin_addr);
	proxy.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	proxy.SetPrefixLength(16);
	proxy.SetProtocol(0);
	proxy.SetTypeProxy();

	// Source ID
	src_id.SetIDNumber(0);
	src_id.SetIDString("192.168.0.0/16");
	src_id.SetIDType(SADB_IDENTTYPE_PREFIX);
	src_id.SetTypeSource();

	// Proposal
	sadb_comb comb = {0};
	proposal.SetReplayWindow(64);
	proposal.AddCombination(comb);

	// Initialize data buffer
	const size_t DATA_LEN = sizeof(struct sadb_msg) + src.GetLengthBytes() + dst.GetLengthBytes() +
			proxy.GetLengthBytes() + src_id.GetLengthBytes() + proposal.GetLengthBytes();
	uint8_t data[DATA_LEN];

	// Serialize individual extensions
	size_t offset = 0;
	struct sadb_msg *hdr = (struct sadb_msg*)(data + offset);
	hdr->sadb_msg_len = DATA_LEN / sizeof(uint64_t);
	hdr->sadb_msg_type = SADB_ACQUIRE;
	hdr->sadb_msg_pid = 512;
	hdr->sadb_msg_seq = 1024;
	hdr->sadb_msg_version = PF_KEY_V2;
	hdr->sadb_msg_satype = SADB_SATYPE_AH;
	hdr->sadb_msg_errno = 0;
	offset += sizeof(struct sadb_msg);

	// Source Address
	size_t len = DATA_LEN - offset;
	status = src.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Destination Address
	len = DATA_LEN - offset;
	status = dst.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Proxy Address
	len = DATA_LEN - offset;
	status = proxy.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Source ID
	len = DATA_LEN - offset;
	status = src_id.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Proposal
	len = DATA_LEN - offset;
	status = proposal.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	PFKeyMessageAcquire msg;
	status = msg.Deserialize(data, DATA_LEN);

	ASSERT_EQ(0, status);

	// Compare header data
	ASSERT_EQ(SADB_ACQUIRE, msg.GetMessageType());
	ASSERT_EQ(512, msg.GetPID());
	ASSERT_EQ(1024, msg.GetSeqNum());
	ASSERT_EQ(SADB_SATYPE_AH, msg.GetSAType());
	ASSERT_EQ(0, msg.GetErrorNum());

	// Compare Source Address
	ASSERT_EQ(32, msg.SourceAddress().GetPrefixLength());
	ASSERT_EQ(0, msg.SourceAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(src.GetAddress(), msg.SourceAddress().GetAddress()));

	// Compare Destination Address
	ASSERT_EQ(32, msg.DestinationAddress().GetPrefixLength());
	ASSERT_EQ(0, msg.DestinationAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(dst.GetAddress(), msg.DestinationAddress().GetAddress()));

	// Compare Proxy Address
	ASSERT_EQ(16, msg.ProxyAddress().GetPrefixLength());
	ASSERT_EQ(0, msg.ProxyAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(proxy.GetAddress(), msg.ProxyAddress().GetAddress()));

	// Compare Source ID
	ASSERT_EQ(true, msg.GetSourceIDPresent());
	ASSERT_EQ(0, msg.SourceID().GetIDNumber());
	ASSERT_EQ(SADB_IDENTTYPE_PREFIX, msg.SourceID().GetIDType());
	ASSERT_EQ(0, strcmp("192.168.0.0/16", msg.SourceID().GetIDString()));

	// Compare Proposal
	ASSERT_EQ(1, msg.Proposal().GetCombinationCount());
	ASSERT_EQ(64, msg.Proposal().GetReplayWindow());
	ASSERT_EQ(0, memcmp(&comb, msg.Proposal().GetCombinationAt(0), sizeof(struct sadb_comb)));
}

TEST(test_PFKeyMessageAcquire, test_Serialize)
{
	std::stringstream sstream;
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	int status;
	struct sockaddr_in ip;
	ip.sin_family = AF_INET;
	ip.sin_port = 0;

	// Begin by initializing extension objects
	PFKeyAddressExtension src;
	PFKeyAddressExtension dst;
	PFKeyAddressExtension proxy;
	PFKeyIdentityExtension src_id;
	PFKeyProposalExtension proposal;

	// Source Address (Gateway)
	inet_pton(AF_INET, "192.168.0.1", &ip.sin_addr);
	src.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	src.SetPrefixLength(32);
	src.SetProtocol(0);
	src.SetTypeSource();

	// Destination Address (Host IP)
	inet_pton(AF_INET, "192.168.0.2", &ip.sin_addr);
	dst.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	dst.SetPrefixLength(32);
	dst.SetProtocol(0);
	dst.SetTypeDestination();

	// Proxy Address (Private Subnet)
	inet_pton(AF_INET, "192.168.0.0", &ip.sin_addr);
	proxy.SetAddress(reinterpret_cast<const sockaddr&>(ip));
	proxy.SetPrefixLength(16);
	proxy.SetProtocol(0);
	proxy.SetTypeProxy();

	// Source ID
	src_id.SetIDNumber(0);
	src_id.SetIDString("192.168.0.0/16");
	src_id.SetIDType(SADB_IDENTTYPE_PREFIX);
	src_id.SetTypeSource();

	// Proposal
	sadb_comb comb = {0};
	proposal.SetReplayWindow(64);
	proposal.AddCombination(comb);

	// Initialize data buffer
	const size_t DATA_LEN = sizeof(struct sadb_msg) + src.GetLengthBytes() + dst.GetLengthBytes() +
			proxy.GetLengthBytes() + src_id.GetLengthBytes() + proposal.GetLengthBytes();
	uint8_t data[DATA_LEN];

	PFKeyMessageAcquire msg;

	msg.SetPID(512);
	msg.SetSeqNum(1024);
	msg.SetSAType(SADB_SATYPE_AH);
	msg.SetErrorNum(0);

	// Add Extensions
	msg.SourceAddress() = src;
	msg.DestinationAddress() = dst;
	msg.ProxyAddress() = proxy;
	msg.SetProxyAddressPresent(true);
	msg.SourceID() = src_id;
	msg.SetSourceIDPresent(true);
	msg.Proposal() = proposal;

	size_t len = DATA_LEN;
	status = msg.Serialize(data, len);

	ASSERT_EQ(0, status);

	PFKeyMessageAcquire msg2;
	status = msg2.Deserialize(data, DATA_LEN);

	ASSERT_EQ(0, status);

	// Compare header data
	ASSERT_EQ(SADB_ACQUIRE, msg2.GetMessageType());
	ASSERT_EQ(512, msg2.GetPID());
	ASSERT_EQ(1024, msg2.GetSeqNum());
	ASSERT_EQ(SADB_SATYPE_AH, msg2.GetSAType());
	ASSERT_EQ(0, msg2.GetErrorNum());

	// Compare Source Address
	ASSERT_EQ(32, msg2.SourceAddress().GetPrefixLength());
	ASSERT_EQ(0, msg2.SourceAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(src.GetAddress(), msg2.SourceAddress().GetAddress()));

	// Compare Destination Address
	ASSERT_EQ(32, msg2.DestinationAddress().GetPrefixLength());
	ASSERT_EQ(0, msg2.DestinationAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(dst.GetAddress(), msg2.DestinationAddress().GetAddress()));

	// Compare Proxy Address
	ASSERT_EQ(16, msg2.ProxyAddress().GetPrefixLength());
	ASSERT_EQ(0, msg2.ProxyAddress().GetProtocol());
	ASSERT_EQ(true, IPUtils::AddressesAreEqual(proxy.GetAddress(), msg2.ProxyAddress().GetAddress()));

	// Compare Source ID
	ASSERT_EQ(true, msg2.GetSourceIDPresent());
	ASSERT_EQ(0, msg2.SourceID().GetIDNumber());
	ASSERT_EQ(SADB_IDENTTYPE_PREFIX, msg2.SourceID().GetIDType());
	ASSERT_EQ(0, strcmp("192.168.0.0/16", msg2.SourceID().GetIDString()));

	// Compare Proposal
	ASSERT_EQ(1, msg2.Proposal().GetCombinationCount());
	ASSERT_EQ(64, msg2.Proposal().GetReplayWindow());
	ASSERT_EQ(0, memcmp(&comb, msg2.Proposal().GetCombinationAt(0), sizeof(struct sadb_comb)));
}
