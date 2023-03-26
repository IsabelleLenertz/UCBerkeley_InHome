#ifndef INC_IPFKEYINTERFACE_HPP_
#define INC_IPFKEYINTERFACE_HPP_

#include "keys/pf_key_v2/messages/PFKeyMessageBase.hpp"

/// <summary>
/// Defines an interface for sending/receiving
/// PF Key messages
/// </summary>
class IPFKeyInterface
{
public:
	virtual ~IPFKeyInterface() {};

	/// <summary
	/// Sends a PF Key message
	/// </summary>
	/// <param name="msg">PF Key message</param>
	/// <returns>Error code</returns>
	virtual int SendMessage(PFKeyMessageBase *msg) = 0;

	/// <summary
	/// Receives a PF Key message
	/// </summary>
	/// <param name="msg">PF Key message</param>
	/// <returns>Error code</returns>
	virtual int ReceiveMessage(PFKeyMessageBase *msg) = 0;

	/// <summary>
	/// Gets a unique sequence number for the
	/// first message in a sequence
	/// </summary>
	/// <returns>Sequence number</returns>
	virtual uint32_t GetUniqueSeqNum() = 0;
};

#endif
