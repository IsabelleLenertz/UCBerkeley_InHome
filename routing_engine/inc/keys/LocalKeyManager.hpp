#ifndef INC_LOCALKEYMANAGER_HPP_
#define INC_LOCALKEYMANAGER_HPP_

#include "keys/IKeyManager.hpp"
#include <vector>

typedef struct
{
	uint32_t spi;
	sockaddr_storage src;
	sockaddr_storage dst;
	uint32_t replay_right; // Sequence number at right side of replay window
	uint32_t replay_map; // Bitmap of last 32 sequence numbers (LSB is lowest seq num)
	std::vector<uint8_t> key;
} key_entry_t;

class LocalKeyManager : public IKeyManager
{
public:
	LocalKeyManager();
	~LocalKeyManager() override;

	int GetKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen);

	int GetSPI(const sockaddr &src, const sockaddr &dst, uint32_t &spi);

	int GetReplayContext(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t &right, uint32_t &map);

	int MarkSequenceNumber(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t seq_num);

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
