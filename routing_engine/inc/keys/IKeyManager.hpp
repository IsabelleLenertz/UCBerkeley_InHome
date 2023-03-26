#ifndef INC_IKEYMANAGER_HPP_
#define INC_IKEYMANAGER_HPP_

#include <arpa/inet.h>
#include <vector>

class IKeyManager
{
public:
	virtual ~IKeyManager() {};

	/// <summary>
	/// Gets the key data associated with the
	/// specified SPI, source address, and
	/// destination address
	/// </summary>
	/// <param name="spi">Security parameters index</param>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="key">Key data out</param>
	/// <param name="keylen">
	/// Input: Length of key output buffer, in bytes
	/// Output: Length of key data, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int GetKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen) = 0;
};



#endif /* INC_KEYS_IKEYMANAGER_HPP_ */
