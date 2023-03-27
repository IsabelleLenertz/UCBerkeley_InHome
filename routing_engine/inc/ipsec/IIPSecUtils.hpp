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
	/// <returns>Error code</returns>
	virtual int ValidateAuthHeader(IIPPacket *pkt) = 0;

	/// <summary>
	/// Validates whether the sequence number in
	/// an IP packet is valid based on the current
	/// replay context. If the sequence number is
	/// valid, updates the replay context accordingly
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <returns>Error code</returns>
	virtual int ValidateAuthHeaderSeqNum(IIPPacket *pkt) = 0;

	/// <summary>
	/// Transforms the authentication header contained
	/// in a packet to use the security association
	/// between the gateway and the destination
	/// </summary>
	/// <param name="pkt">IP packet</param>
	/// <returns>Error Code</returns>
	virtual int TransformAuthHeader(IIPPacket *pkt) = 0;

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
