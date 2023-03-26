#include "keys/KeyUtils.hpp"

#include "status/error_codes.hpp"

int KeyUtils::FromHexString(const std::string &str, uint8_t *key, size_t len)
{
	// Verify key string length is divisible by 2
	if (str.size() % 2 != 0)
	{
		return PF_KEY_ERROR_INVALID_KEY_LENGTH;
	}

	// Verify enough room for key data
	if (len < str.size() / 2)
	{
		return PF_KEY_ERROR_OVERFLOW;
	}

	size_t str_index = 0;
	size_t out_index = 0;
	while (str_index < str.size())
	{
		uint8_t *b = key + out_index;
		*b = (uint8_t)(strtoul(str.substr(str_index, 2).c_str(), NULL, 16));

		str_index += 2;
		out_index += 1;
	}
}
