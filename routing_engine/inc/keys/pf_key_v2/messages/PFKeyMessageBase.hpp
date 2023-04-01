#ifndef INC_PFKEYMESSAGEBASE_HPP_
#define INC_PFKEYMESSAGEBASE_HPP_

#include <cstdint>
#include <cstdlib>
#include <linux/pfkeyv2.h>

class PFKeyMessageBase
{
public:
	virtual ~PFKeyMessageBase();

	/// <summary>
	/// Serializes this PF_KEY message
	/// </summary>
	/// <param name="buff">Output buffer</param>
	/// <param name="len">
	/// Input: Length of output buffer, in bytes
	/// Output: Length of serialized message, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int Serialize(uint8_t *buff, size_t &len) = 0;

	/// <summary>
	/// Deserializes the PF_KEY message from binary input
	/// </summary>
	/// <param name="data">Input data</param>
	/// <param name="len">Length of input data, in bytes</param>
	/// <returns>Error code</returns>
	virtual int Deserialize(const uint8_t *data, size_t len) = 0;

	/// <summary>
	/// Gets the error number
	/// </summary>
	/// <returns>Error number</returns>
	uint8_t GetErrorNum();

	/// <summary>
	/// Sets the error number
	/// </summary>
	/// <param name="num">Error number</param>
	void SetErrorNum(uint8_t num);

	/// <summary>
	/// Gets the security association (SA) type
	/// </summary>
	/// <returns>SA type</returns>
	uint8_t GetSAType();

	/// <summary>
	/// Sets the security association (SA) type
	/// </summary>
	/// <param name="type">SA type</param>
	void SetSAType(uint8_t type);

	/// <summary>
	/// Gets the sequence number
	/// </summary>
	/// <returns>Sequence number</returns>
	uint32_t GetSeqNum();

	/// <summary>
	/// Sets the sequence number
	/// </summary>
	/// <param name="num">Sequence number</param>
	void SetSeqNum(uint32_t num);

	/// <summary>
	/// Gets the process ID
	/// </summary>
	/// <returns>Process ID</returns>
	uint32_t GetPID();

	/// <summary>
	/// Sets the process ID
	/// </summary>
	/// <returns>Process ID</returns>
	void SetPID(uint32_t pid);

	/// <summary>
	/// Gets the message type
	/// </summary>
	/// <returns>Message type</returns>
	virtual uint8_t GetMessageType() = 0;

	/// <summary>
	/// Gets the length of the message, in bytes
	/// </summary>
	/// <returns>Length of message, in bytes</returns>
	virtual size_t GetLengthBytes() = 0;

protected:
	struct sadb_msg _header;
};

#endif
