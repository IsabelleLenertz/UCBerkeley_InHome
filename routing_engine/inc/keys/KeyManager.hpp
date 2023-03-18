#ifndef INC_KEYMANAGER_HPP_
#define INC_KEYMANAGER_HPP_

#include "keys/IKeyManager.hpp"

class KeyManager : public IKeyManager
{
public:
	KeyManager();
	~KeyManager() override;

	/// <summary>
	/// Defines the set of proposals to be provided when
	/// a key pair is acquired.
	/// </summary>
	/// <param name="combs">Parameter combinations</param>
	/// <returns>Error code</returns>
	int SetProposal(const std::vector<struct sadb_comb> combs);

	/// <summary>
	/// Initiates a key exchange using the specified source (local)
	/// and destination (peer) addresses.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <returns>
	int AcquireKey(const struct sockaddr &src, const struct sockaddr &dst);

	/// <summary>
	/// Deletes the key associated with the specified source/destination address pair.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	int DeleteKey(const struct sockaddr &src, const struct sockaddr &dst);

	/// <summary>
	/// Sets the callback used to process updates security associations
	/// </summary>
	int SetSAUpdatedCallback(UpdateSACallback_t callback);

private:
	/// <summary>
	/// Processes an update message by sending an SADB_GET message to the kernel
	/// to request the updated security association for the specified SPI.
	/// Passes the update SA information to the OnSAUpdated callback.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="spi">Security Parameters Index</param>
	int ProcessUpdate(const struct sockaddr &src, const struct sockaddr &dst, uint32_t spi);

	UpdateSACallback_t _update_sa_callback;
};

#endif
