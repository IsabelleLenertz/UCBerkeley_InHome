#ifndef INC_IPSEC_IIPSECUTILS_HPP_
#define INC_IPSEC_IIPSECUTILS_HPP_

#include "layer3/IIPPacket.hpp"

class IIPSecUtils
{
public:
	/// <summary>
	/// Validates the Integrity Check Value (ICV)
	/// contained in an IP packet with an authentication
	/// header
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <returns>True if valid, false otherwise</returns>
	virtual bool ValidateAuthHeader(IIPPacket *pkt) = 0;

	/// <summary>
	/// Calculates the value of the ICV
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <param name="icv_out">ICV data out</param>
	/// <param name="len">Length of ICV data</param>
	/// <returns>Error code</returns>
	virtual int CalculateICV(IIPPacket *pkt, uint8_t *icv_out, size_t len) = 0;
};

#endif
