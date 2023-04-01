#include "ipsec/NullIPSecUtils.hpp"

#include "layer3/IPPacketFactory.hpp"
#include "layer3/IPUtils.hpp"
#include "ipsec/IPSecAuthHeader.hpp"
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "logging/Logger.hpp"

NullIPSecUtils::NullIPSecUtils(IKeyManager *key_manager)
{
	_key_manager = key_manager;
}

NullIPSecUtils::~NullIPSecUtils()
{
}

int NullIPSecUtils::ValidateAuthHeader(IIPPacket *pkt)
{
	return NO_ERROR;
}

int NullIPSecUtils::CalculateICV(IIPPacket *pkt, uint8_t *icv_out, size_t len)
{
	memset(icv_out, 0, len);
	return NO_ERROR;
}

int NullIPSecUtils::TransformAuthHeader(IIPPacket *pkt)
{
	return NO_ERROR;
}

int NullIPSecUtils::ValidateAuthHeaderSeqNum(IIPPacket *pkt)
{
	return NO_ERROR;
}
