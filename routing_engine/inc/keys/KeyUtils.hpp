#ifndef INC_KEYUTILS_HPP_
#define INC_KEYUTILS_HPP_

#include <cstdint>
#include <cstdlib>
#include <string>

class KeyUtils
{
public:
	static int FromHexString(const std::string &str, uint8_t *key, size_t len);
};

#endif
