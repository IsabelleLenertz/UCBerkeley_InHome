#include <gtest/gtest.h>
#include "keys/pf_key_v2/messages/PFKeyMessageUpdate.hpp"
#include <arpa/inet.h>
#include "logging/Logger.hpp"
#include <cstring>

TEST(test_PFKeyMessageUpdate, test_Deserialize)
{
	std::stringstream sstream;
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	int status;
	struct sockaddr_in ip;
	ip.sin_family = AF_INET;
	ip.sin_port = 0;

	// Begin by initializing extension objects
	PFKeyAssociationExtension assoc;
	PFKeyAddressExtension src;
	PFKeyAddressExtension dst;
	PFKeyAddressExtension proxy;
	PFKeyKeyExtension auth_key;
	PFKeyKeyExtension encrypt_key;

	// Association
	assoc.SetAuthAlgorithm(SADB_X_AALG_SHA2_256HMAC);
	assoc.SetEncryptAlgorithm(SADB_X_EALG_AES_GCM_ICV8);
	assoc.SetFlags(SADB_SAFLAGS_PFS);
	assoc.SetReplayWindow(64);
	assoc.SetSPI(512);
	assoc.SetState(SADB_SASTATE_MATURE);

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

	// Authentication Key
	const size_t AUTH_KEY_LEN = 64;
	const size_t AUTH_KEY_BITS = 512;
	const uint8_t auth_key_data[AUTH_KEY_LEN] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	};
	auth_key.SetKeyData(auth_key_data, AUTH_KEY_LEN, AUTH_KEY_BITS);
	auth_key.SetTypeAuth();

	// Encryption Key
	const size_t ENCRYPT_KEY_LEN = 64;
	const size_t ENCRYPT_KEY_BITS = 512;
	const uint8_t encrypt_key_data[ENCRYPT_KEY_LEN] = {
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7
	};
	encrypt_key.SetKeyData(encrypt_key_data, ENCRYPT_KEY_LEN, ENCRYPT_KEY_BITS);
	encrypt_key.SetTypeEncrypt();

	// Initialize data buffer
	const size_t DATA_LEN = sizeof(struct sadb_msg) + assoc.GetLengthBytes() + src.GetLengthBytes() +
			dst.GetLengthBytes() + proxy.GetLengthBytes() + auth_key.GetLengthBytes() + encrypt_key.GetLengthBytes();
	uint8_t data[DATA_LEN];

	// Serialize individual extensions
	size_t offset = 0;
	struct sadb_msg *hdr = (struct sadb_msg*)(data + offset);
	hdr->sadb_msg_len = DATA_LEN / sizeof(uint64_t);
	hdr->sadb_msg_type = SADB_UPDATE;
	hdr->sadb_msg_pid = 512;
	hdr->sadb_msg_seq = 1024;
	hdr->sadb_msg_version = PF_KEY_V2;
	hdr->sadb_msg_satype = SADB_SATYPE_AH;
	hdr->sadb_msg_errno = 0;
	offset += sizeof(struct sadb_msg);

	// Association
	size_t len = DATA_LEN - offset;
	status = assoc.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Source Address
	len = DATA_LEN - offset;
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

	// Authentication Key
	len = DATA_LEN - offset;
	status = auth_key.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	// Encryption Key
	len = DATA_LEN - offset;
	status = encrypt_key.Serialize(data + offset, len);
	ASSERT_EQ(0, status);
	offset += len;

	PFKeyMessageUpdate msg;
	status = msg.Deserialize(data, DATA_LEN);

	ASSERT_EQ(0, status);

	// Compare header data
	ASSERT_EQ(SADB_UPDATE, msg.GetMessageType());
	ASSERT_EQ(512, msg.GetPID());
	ASSERT_EQ(1024, msg.GetSeqNum());
	ASSERT_EQ(SADB_SATYPE_AH, msg.GetSAType());
	ASSERT_EQ(0, msg.GetErrorNum());

	// Compare association
	ASSERT_EQ(SADB_X_AALG_SHA2_256HMAC, assoc.GetAuthAlgorithm());
	ASSERT_EQ(SADB_X_EALG_AES_GCM_ICV8, assoc.GetEncryptAlgorithm());
	ASSERT_EQ(SADB_SAFLAGS_PFS, assoc.GetFlags());
	ASSERT_EQ(64, assoc.GetReplayWindow());
	ASSERT_EQ(512, assoc.GetSPI());
	ASSERT_EQ(SADB_SASTATE_MATURE, assoc.GetState());

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

	// Compare Authentication Key
	ASSERT_EQ(SADB_EXT_KEY_AUTH, msg.AuthKey().GetType());
	ASSERT_EQ(512, msg.AuthKey().GetNumKeyBits());
	const uint8_t *read_auth_key_data;
	size_t read_auth_key_len = msg.AuthKey().GetKeyData(read_auth_key_data);
	ASSERT_EQ(AUTH_KEY_LEN, read_auth_key_len);
	ASSERT_EQ(0, memcmp(auth_key_data, read_auth_key_data, AUTH_KEY_LEN));

	// Compare Encryption Key
	ASSERT_EQ(SADB_EXT_KEY_ENCRYPT, msg.EncryptKey().GetType());
	ASSERT_EQ(512, msg.EncryptKey().GetNumKeyBits());
	const uint8_t *read_encrypt_key_data;
	size_t read_encrypt_key_len = msg.EncryptKey().GetKeyData(read_encrypt_key_data);
	ASSERT_EQ(ENCRYPT_KEY_LEN, read_encrypt_key_len);
	ASSERT_EQ(0, memcmp(encrypt_key_data, read_encrypt_key_data, ENCRYPT_KEY_LEN));
}

TEST(test_PFKeyMessageUpdate, test_Serialize)
{
	std::stringstream sstream;
	Logger::SetLogLevel(LOG_VERBOSE);
	Logger::SetLogStdOut(true);

	int status;
	struct sockaddr_in ip;
	ip.sin_family = AF_INET;
	ip.sin_port = 0;

	// Begin by initializing extension objects
	PFKeyAssociationExtension assoc;
	PFKeyAddressExtension src;
	PFKeyAddressExtension dst;
	PFKeyAddressExtension proxy;
	PFKeyKeyExtension auth_key;
	PFKeyKeyExtension encrypt_key;

	// Association
	assoc.SetAuthAlgorithm(SADB_X_AALG_SHA2_256HMAC);
	assoc.SetEncryptAlgorithm(SADB_X_EALG_AES_GCM_ICV8);
	assoc.SetFlags(SADB_SAFLAGS_PFS);
	assoc.SetReplayWindow(64);
	assoc.SetSPI(512);
	assoc.SetState(SADB_SASTATE_MATURE);

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

	// Authentication Key
	const size_t AUTH_KEY_LEN = 64;
	const size_t AUTH_KEY_BITS = 512;
	const uint8_t auth_key_data[AUTH_KEY_LEN] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	};
	auth_key.SetKeyData(auth_key_data, AUTH_KEY_LEN, AUTH_KEY_BITS);
	auth_key.SetTypeAuth();

	// Encryption Key
	const size_t ENCRYPT_KEY_LEN = 64;
	const size_t ENCRYPT_KEY_BITS = 512;
	const uint8_t encrypt_key_data[ENCRYPT_KEY_LEN] = {
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7
	};
	encrypt_key.SetKeyData(encrypt_key_data, ENCRYPT_KEY_LEN, ENCRYPT_KEY_BITS);
	encrypt_key.SetTypeEncrypt();

	// Initialize data buffer
	const size_t DATA_LEN = sizeof(struct sadb_msg) + assoc.GetLengthBytes() + src.GetLengthBytes() +
			dst.GetLengthBytes() + proxy.GetLengthBytes() + auth_key.GetLengthBytes() + encrypt_key.GetLengthBytes();
	uint8_t data[DATA_LEN];

	PFKeyMessageUpdate msg;

	msg.SetPID(512);
	msg.SetSeqNum(1024);
	msg.SetSAType(SADB_SATYPE_AH);
	msg.SetErrorNum(0);

	msg.Association() = assoc;
	msg.SourceAddress() = src;
	msg.DestinationAddress() = dst;
	msg.ProxyAddress() = proxy;
	msg.SetProxyAddressPresent(true);
	msg.AuthKey() = auth_key;
	msg.SetAuthKeyPresent(true);
	msg.EncryptKey() = encrypt_key;
	msg.SetEncryptKeyPresent(true);

	size_t len = DATA_LEN;
	status = msg.Serialize(data, len);

	ASSERT_EQ(0, status);

	PFKeyMessageUpdate msg2;
	size_t len2 = DATA_LEN;
	status = msg2.Deserialize(data, len2);
	ASSERT_EQ(len, len2);

	ASSERT_EQ(0, status);

	// Compare header data
	ASSERT_EQ(SADB_UPDATE, msg2.GetMessageType());
	ASSERT_EQ(512, msg2.GetPID());
	ASSERT_EQ(1024, msg2.GetSeqNum());
	ASSERT_EQ(SADB_SATYPE_AH, msg2.GetSAType());
	ASSERT_EQ(0, msg2.GetErrorNum());

	// Compare association
	ASSERT_EQ(SADB_X_AALG_SHA2_256HMAC, assoc.GetAuthAlgorithm());
	ASSERT_EQ(SADB_X_EALG_AES_GCM_ICV8, assoc.GetEncryptAlgorithm());
	ASSERT_EQ(SADB_SAFLAGS_PFS, assoc.GetFlags());
	ASSERT_EQ(64, assoc.GetReplayWindow());
	ASSERT_EQ(512, assoc.GetSPI());
	ASSERT_EQ(SADB_SASTATE_MATURE, assoc.GetState());

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

	// Compare Authentication Key
	ASSERT_EQ(SADB_EXT_KEY_AUTH, msg2.AuthKey().GetType());
	ASSERT_EQ(512, msg2.AuthKey().GetNumKeyBits());
	const uint8_t *read_auth_key_data;
	size_t read_auth_key_len = msg2.AuthKey().GetKeyData(read_auth_key_data);
	ASSERT_EQ(AUTH_KEY_LEN, read_auth_key_len);
	ASSERT_EQ(0, memcmp(auth_key_data, read_auth_key_data, AUTH_KEY_LEN));

	// Compare Encryption Key
	ASSERT_EQ(SADB_EXT_KEY_ENCRYPT, msg2.EncryptKey().GetType());
	ASSERT_EQ(512, msg2.EncryptKey().GetNumKeyBits());
	const uint8_t *read_encrypt_key_data;
	size_t read_encrypt_key_len = msg2.EncryptKey().GetKeyData(read_encrypt_key_data);
	ASSERT_EQ(ENCRYPT_KEY_LEN, read_encrypt_key_len);
	ASSERT_EQ(0, memcmp(encrypt_key_data, read_encrypt_key_data, ENCRYPT_KEY_LEN));
}
