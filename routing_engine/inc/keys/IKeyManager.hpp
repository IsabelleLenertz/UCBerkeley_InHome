#ifndef INC_IKEYMANAGER_HPP_
#define INC_IKEYMANAGER_HPP_

#include <linux/pfkeyv2.h>
#include <cstdint>
#include <vector>
#include <functional>

/// <summary>
/// Defines a callback for processing updates
/// to security associations
/// </summary>
/// <param name="src">Source address</param>
/// <param name="dst">Destination address</param>
/// <param name="sa">Security association</param>
typedef std::function<void(const struct sockaddr &src, const struct sockaddr &dst, const struct sadb_sa &sa)> UpdateSACallback_t;

class IKeyManager
{
public:
	virtual ~IKeyManager() {};

	/// <summary>
	/// Defines the set of proposals to be provided when
	/// a key pair is acquired.
	/// </summary>
	/// <param name="combs">Parameter combinations</param>
	/// <returns>Error code</returns>
	virtual int SetProposal(const std::vector<struct sadb_comb> combs) = 0;

	/// <summary>
	/// Initiates a key exchange using the specified source (local)
	/// and destination (peer) addresses.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <returns>
	virtual int AcquireKey(const struct sockaddr &src, const struct sockaddr &dst) = 0;

	/// <summary>
	/// Deletes the key associated with the specified source/destination address pair.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	virtual int DeleteKey(const struct sockaddr &src, const struct sockaddr &dst) = 0;

	/// <summary>
	/// Sets the callback used to process updates security associations
	/// </summary>
	virtual int SetSAUpdatedCallback(UpdateSACallback_t callback) = 0;
};

#endif
