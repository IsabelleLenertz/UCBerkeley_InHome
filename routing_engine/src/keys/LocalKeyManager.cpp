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

int LocalKeyManager::GetSPI(const sockaddr &src, const sockaddr &dst, uint32_t &spi)
{
	for (auto e = _keys.begin(); e < _keys.end(); e++)
	{
		key_entry_t &entry = *e;

		if (IPUtils::AddressesAreEqual(src, reinterpret_cast<const sockaddr&>(entry.src)) &&
			IPUtils::AddressesAreEqual(dst, reinterpret_cast<const sockaddr&>(entry.dst)))
		{
			spi = entry.spi;
			return NO_ERROR;
		}
	}

	return PF_KEY_ERROR_KEY_NOT_FOUND;
}


int LocalKeyManager::GetReplayContext(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t &right, uint32_t &map)
{
	for (auto e = _keys.begin(); e < _keys.end(); e++)
	{
		key_entry_t &entry = *e;

		if (spi == entry.spi &&
			IPUtils::AddressesAreEqual(src, reinterpret_cast<const sockaddr&>(entry.src)) &&
			IPUtils::AddressesAreEqual(dst, reinterpret_cast<const sockaddr&>(entry.dst)))
		{
			right = entry.replay_right;
			map = entry.replay_map;
			return NO_ERROR;
		}
	}

	return PF_KEY_ERROR_KEY_NOT_FOUND;
}

int LocalKeyManager::MarkSequenceNumber(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t seq_num)
{
	for (auto e = _keys.begin(); e < _keys.end(); e++)
	{
		key_entry_t &entry = *e;

		if (spi == entry.spi &&
			IPUtils::AddressesAreEqual(src, reinterpret_cast<const sockaddr&>(entry.src)) &&
			IPUtils::AddressesAreEqual(dst, reinterpret_cast<const sockaddr&>(entry.dst)))
		{
			// Check if the sequence number shifts the window
			if (seq_num > entry.replay_right)
			{
				int shift_count = seq_num - entry.replay_right;
				shift_count = (shift_count < 31) ? shift_count : 31;

				// Shift and mark map
				entry.replay_map >>= shift_count;
				entry.replay_map |= 0x80000000;

				// Set right edge of map
				entry.replay_right = seq_num;
			}
			// Check if the sequence number is within the current window
			else if (seq_num >= entry.replay_right - 31)
			{
				int shift_count = entry.replay_right - seq_num;

				// Shift marker
				uint32_t marker = 0x80000000;
				marker >>= shift_count;

				// Mark map
				entry.replay_map |= marker;
			}

			return NO_ERROR;
		}
	}

	return PF_KEY_ERROR_KEY_NOT_FOUND;
}

void LocalKeyManager::AddKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, const uint8_t *key, size_t keylen)
{
	key_entry_t new_entry;
	new_entry.spi = spi;
	new_entry.replay_right = 32;
	new_entry.replay_map = 0;
	IPUtils::StoreSockaddr(src, new_entry.src);
	IPUtils::StoreSockaddr(dst, new_entry.dst);
	new_entry.key = std::vector<uint8_t>(key, key + keylen);

	_keys.push_back(new_entry);
}

