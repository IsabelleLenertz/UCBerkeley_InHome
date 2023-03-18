#ifndef INC_PFKEYV2MESSAGEACQUIRE_HPP_
#define INC_PFKEYV2MESSAGEACQUIRE_HPP_

#include "keys/pf_key_v2/PFKeyV2MessageBase.hpp"
#include <sys/socket.h>
#include <vector>

class PFKeyV2MessageAcquire : public PFKeyV2MessageBase
{
public:
	PFKeyV2MessageAcquire();
	~PFKeyV2MessageAcquire() override;

	int Serialize(uint8_t *buff, size_t &len);

	int Deserialize(uint8_t *data, size_t len);

	uint8_t GetMessageType();

	/// <summary>
	/// Gets the source address
	/// </summary>
	/// <param name="prefix_len">Prefix length out</param>
	/// <param name="protocol">Layer 4 protocol out</param>
	/// <returns>Source address</returns>
	const struct sockaddr& GetSourceAddress(uint8_t &prefix_len, uint8_t &protocol);

	/// <summary>
	/// Gets the destination address
	/// </summary>
	/// <param name="prefix_len">Prefix length out</param>
	/// <param name="protocol">Layer 4 protocol out</param>
	/// <returns>Destination address</returns>
	const struct sockaddr& GetDestinationAddress(uint8_t &prefix_len, uint8_t &protocol);

	/// <summary>
	/// Sets the source address
	/// </summary>
	/// <param name="addr">Source address</param>
	/// <param name="prefix_len">Prefix length</param>
	/// <param name="protocol">Layer 4 Protocol</param>
	/// <remarks>
	/// If the port field of the sockaddr is non-zero,
	/// then the layer 4 protocol MUST be specified
	/// </remarks>
	void SetSourceAddress(const struct sockaddr &addr, uint8_t prefix_len, uint8_t protocol = 0);

	/// <summary>
	/// Sets the destination address
	/// </summary>
	/// <param name="addr">Destination address</param>
	/// <param name="prefix_len">Prefix length</param>
	/// <param name="protocol">Layer 4 Protocol</param>
	/// <remarks>
	/// If the port field of the sockaddr is non-zero,
	/// then the layer 4 protocol MUST be specified
	/// </remarks>
	void SetDestinationAddress(const struct sockaddr &addr, uint8_t prefix_len, uint8_t protocol = 0);

	/// <summary>
	/// Adds a proposed combination of security parameters
	/// to the list of proposed combinations
	/// </summary>
	/// <param name="comb">Parameter combination</param>
	void AddProposedParameters(const struct sadb_comb &comb);

	/// <summary>
	/// Gets the replay window
	/// </summary>
	uint32_t GetReplayWindow();

	/// <summary>
	/// Sets the replay window
	/// </summary>
	/// <param name="replay">Replay window</param>
	void SetReplayWindow(uint32_t replay);

private:
	struct sockaddr_storage _src_addr;
	uint8_t _src_prefix;
	uint8_t _src_protocol;
	struct sockaddr_storage _dst_addr;
	uint8_t _dst_prefix;
	uint8_t _dst_protocol;
	std::vector<struct sadb_comb> _combs;

	uint32_t _replay_window;
};

#endif
