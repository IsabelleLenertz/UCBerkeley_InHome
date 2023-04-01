#ifndef INC_PFKEYMESSAGEFACTORY_HPP_
#define INC_PFKEYMESSAGEFACTORY_HPP_

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"
#include <cstdint>
#include <cstdlib>

class PFKeyMessageFactory
{
public:
	static PFKeyMessageBase *Build(const uint8_t *buff, size_t len);
};

#endif
