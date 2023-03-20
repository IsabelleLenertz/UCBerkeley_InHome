#ifndef INC_LOCALKEYMANAGER_HPP_
#define INC_LOCALKEYMANAGER_HPP_

#include "keys/IKeyManager.hpp"
#include <vector>

typedef struct
{
	uint32_t spi;
	sockaddr_storage src;
	sockaddr_storage dst;
	std::vector<uint8_t> key;
} key_entry_t;

class LocalKeyManager : public IKeyManager
{
public:
	LocalKeyManager();
	~LocalKeyManager() override;

	void Synchronize();

	int GetKey(const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen);

	int GetKey(uint32_t spi, uint8_t *key, size_t &keylen);

	/// <summary>
	/// Adds a key to the key management database
	/// </summary>
	/// <param name="spi">Security parameters index</param>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="key">Key data</param>
	/// <param name="keylen>Length of key, in bytes</param>
	void AddKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, const uint8_t *key, size_t keylen);

private:
	std::vector<key_entry_t> _keys;
};

#endif
