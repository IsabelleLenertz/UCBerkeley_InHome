#ifndef INC_PFKEYV2MESSAGEBASE_HPP_
#define INC_PFKEYV2MESSAGEBASE_HPP_

#include <linux/pfkeyv2.h>
#include <cstdint>
#include <cstdlib>

class PFKeyV2MessageBase
{
public:
	PFKeyV2MessageBase();
	virtual ~PFKeyV2MessageBase();

	/// <summary>
	/// Serializes the PF_KEY message into the specified
	/// data buffer.
	/// </summary>
	/// <param name="buff">Data buffer</param>
	/// <param name="len">
	/// Input: Length of buffer, in bytes
	/// Output: Length of serialized message
	/// </param>
	/// <returns>Error code</returns>
	/// <remarks>
	/// If the return value is non-zero, then the content
	/// of buff and the value of len are undefined
	/// </remarks>
	virtual int Serialize(uint8_t *buff, size_t &len) = 0;

	/// <summary>
	/// Deserializes the PF_KEY message from the specified
	/// raw data buffer.
	/// </summary>
	/// <param name="data">Data buffer</param>
	/// <param name="len">Length of data, in bytes</param>
	/// <returns>Error code</returns>
	/// <remarks>
	/// If the return value is non-zero, then the contents
	/// of this object are undefined
	/// </remarks>
	virtual int Deserialize(const uint8_t *data, size_t len) = 0;

	/// <summary>
	/// Gets the message type for this PF_KEY message
	/// </summary>
	/// <returns>Message type</returns>
	virtual uint8_t GetMessageType() = 0;

	/// <summary>
	/// Gets the error code for this PF_KEY message
	/// </summary>
	/// <returns>Error code</returns>
	uint8_t GetErrorCode();

	/// <summary>
	/// Gets the security association (SA) type
	/// for this PF_KEY message
	/// </summary>
	/// <returns>SA Type</returns>
	uint8_t GetSAType();

	/// <summary>
	/// Sets the security association (SA) type
	/// for this PF_KEY message
	/// </summary>
	/// <param name="type">SA Type</param>
	void SetSAType(uint8_t type);

	/// <summary>
	/// Gets the sequence number for this PF_KEY message
	/// </summary>
	/// <returns>Sequence number</returns>
	uint32_t GetSequenceNumber();

	/// <summary>
	/// Sets the sequence number for this PF_KEY message
	/// </summary>
	/// <param name="num">Sequence number</param>
	void SetSequenceNumber(uint32_t num);

	/// <summary>
	/// Gets the process ID (PID) for this PF_KEY message
	/// </summary>
	/// <returns>PID number</returns>
	uint32_t GetPID();

	/// <summary>
	/// Sets the process ID (PID) for this PF_KEY message
	/// </summary>
	/// <param name="pid">PID number</param>
	void SetPID(uint32_t pid);

protected:
	uint8_t _err_code;
	uint8_t _sa_type;
	uint32_t _seq_num;
	uint32_t _pid;
};

#endif
