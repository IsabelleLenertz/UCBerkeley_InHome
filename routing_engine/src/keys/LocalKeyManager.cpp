#include "keys/LocalKeyManager.hpp"
#include "layer3/IPUtils.hpp"
#include <cstring>
#include "status/error_codes.hpp"

LocalKeyManager::LocalKeyManager()
	: _keys()
{
}

LocalKeyManager::~LocalKeyManager()
{
}

int LocalKeyManager::GetKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen)
{
	for (auto e = _keys.begin(); e < _keys.end(); e++)
	{
		key_entry_t &entry = *e;

		if (spi == entry.spi &&
			IPUtils::AddressesAreEqual(src, reinterpret_cast<const sockaddr&>(entry.src)) &&
			IPUtils::AddressesAreEqual(dst, reinterpret_cast<const sockaddr&>(entry.dst)))
		{
			memcpy(key, entry.key.data(), entry.key.size());
			keylen = entry.key.size();
			return NO_ERROR;
		}
	}

	return PF_KEY_ERROR_KEY_NOT_FOUND;
}

void LocalKeyManager::AddKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, const uint8_t *key, size_t keylen)
{
	key_entry_t new_entry;
	new_entry.spi = spi;
	IPUtils::StoreSockaddr(src, new_entry.src);
	IPUtils::StoreSockaddr(dst, new_entry.dst);
	new_entry.key = std::vector<uint8_t>(key, key + keylen);

	_keys.push_back(new_entry);
}
