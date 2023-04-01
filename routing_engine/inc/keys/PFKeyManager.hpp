#ifndef INC_PFKEYMANAGER_HPP_
#define INC_PFKEYMANAGER_HPP_

#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <mutex>
#include <thread>

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"
#include "keys/pf_key_v2/PFKeySecurityAssociation.hpp"
#include "keys/IKeyManager.hpp"
#include "keys/pf_key_v2/IPFKeyInterface.hpp"

class PFKeyManager : public IKeyManager, IPFKeyInterface
{
public:
	PFKeyManager();
	~PFKeyManager() override;

	int GetKey(uint32_t spi, const struct sockaddr &src, const struct sockaddr &dst, uint8_t *key, size_t &keylen);
	int GetSPI(const sockaddr &src, const sockaddr &dst, uint32_t &spi);
	int GetReplayContext(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t &right, uint32_t *map);
	int MarkSequenceNumber(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t seq_num);

	int SendMessage(PFKeyMessageBase *msg);
	int ReceiveMessage(PFKeyMessageBase *msg);
	uint32_t GetUniqueSeqNum();

	/// <summary>
	/// Adds a new host
	/// </summary>
	/// <param name="host">IP address of host</param>
	/// <returns>Error code</returns>
	int AddHost(const sockaddr &host);

	/// <summary>
	/// Removes an existing host
	/// </summary>
	/// <param name="host">IP address of host</param>
	/// <returns>Error code</returns>
	int RemoveHost(const sockaddr &host);

	/// <summary>
	/// Removes any SAs which are in the "Closed" state
	/// </summary>
	void RemoveClosedSAs();

	/// <summary>
	/// Opens the PF Key socket and
	/// begins the receive loop
	/// </summary>
	/// <returns>True if successful</returns>
	int Initialize();

private:
	/// <summary>
	/// Receives messages from the PF Key
	/// socket and dispatches them to
	/// active security association objects
	/// </summary>
	void _receive_loop();

	/// <summary>
	/// Builds an acquire message suitable to acquire
	/// a security association from the specified host
	/// IP to the specified gateway IP
	/// </summary>
	/// <param name="host">Host IP</param>
	/// <param name="gateway">Gateway IP</param>
	/// <param name="msg">Acquire message out</param>
	void _build_from_host_acquire(const sockaddr &host, const sockaddr &gateway, PFKeyMessageAcquire *msg);

	/// <summary>
	/// Builds an acquire message suitable to acquire
	/// a security association to the specified host
	/// IP from the specified gateway IP
	/// </summary>
	/// <param name="host">Host IP</param>
	/// <param name="gateway">Gateway IP</param>
	/// <param name="msg">Acquire message out</param>
	void _build_to_host_acquire(const sockaddr &host, const sockaddr &gateway, PFKeyMessageAcquire *msg);

	/// <summary>
	/// Initializes a set of default extension objects
	/// which will be frequently used
	/// </summary>
	void _initialize_default_extensions();

	/// <summary>
	/// Given a host IP, drives the gateway IP,
	/// </summary>
	/// <param name="host_ip">Host IP address</param>
	/// <param name="gateway">Gateway IP out</param>
	/// <remarks>
	/// Assumes that the host exists on a subnet with
	/// exactly 4 addresses. For IPv4, this means that
	/// the prefix length is /30. The gateway address
	/// is defined as the first host address on the subnet
	/// </remarks>
	void _derive_gateway(const struct sockaddr &host_ip, struct sockaddr &gateway);

	PFKeySecurityAssociation *_get_association_by_seq_num(uint32_t seq_num);
	PFKeySecurityAssociation *_get_association_by_src_addr(const sockaddr &src);
	PFKeySecurityAssociation *_get_association_by_dst_addr(const sockaddr &dst);

	// Default Extensions
	PFKeyProposalExtension _default_proposal;
	PFKeyAddressExtension _private_subnet_addr_v4;
	PFKeyIdentityExtension _private_subnet_id_v4;

	int _socket_d;

	static const size_t PF_KEY_BUFF_SIZE = 2048;
	uint8_t _rcv_buff[PF_KEY_BUFF_SIZE];
	uint8_t _send_buff[PF_KEY_BUFF_SIZE];
	bool _exiting;
	pid_t _pid;
	uint32_t _next_seq_num;

	std::mutex _db_mutex;
	std::mutex _send_mutex;
	std::mutex _rcv_mutex;

	std::thread _th;

	const uint64_t SA_TIMEOUT_1DAY = 86400;
	const uint64_t SA_LIFETIME_1TB = 1099511627776;

	const char* PRIVATE_SUBNET_STRING = "192.168.0.0/16";

	std::vector<PFKeySecurityAssociation> _associations;
};

#endif
