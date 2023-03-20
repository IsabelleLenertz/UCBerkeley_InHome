#ifndef INC_IKEYMANAGER_HPP_
#define INC_IKEYMANAGER_HPP_

#include <arpa/inet.h>

class IKeyManager
{
public:
	virtual ~IKeyManager() {};

	/// <summary>
	/// Begin synchronizing the local key management
	/// database with the policy database
	/// </summary>
	virtual void Synchronize() = 0;

	/// <summary>
	/// Gets the key data associated with the
	/// specified source and desination addresses.
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="key">Key data out</param>
	/// <param name="keylen">
	/// Input: Length of key output buffer, in bytes
	/// Output: Length of key data, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int GetKey(const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen) = 0;

	/// <summary>
	/// Gets the key associated with the
	/// specified security parameters index (SPI).
	/// </summary>
	/// <param name="spi">Security Parameters Index</param>
	/// <param name="key">Key data out</param>
	/// <param name="keylen">
	/// Input: Length of key output buffer, in bytes
	/// Output: Length of key data, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int GetKey(uint32_t spi, uint8_t *key, size_t &keylen) = 0;
};



#endif /* INC_KEYS_IKEYMANAGER_HPP_ */
