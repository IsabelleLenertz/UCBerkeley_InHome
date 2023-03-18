#ifndef INC_IPFKEYEXTENSION_HPP_
#define INC_IPFKEYEXTENSION_HPP_

#include <cstdint>
#include <cstdlib>
#include <linux/pfkeyv2.h>

/// <summary>
/// Generic interface for PF Key extension classes
/// </summary>
class IPFKeyExtension
{
public:
	virtual ~IPFKeyExtension(){};

	/// <summary>
	/// Serializes the extension to a form suitable
	/// for inclusion in a PF_KEY_V2 message
	/// </summary>
	/// <param name="buff">Data buffer out</param>
	/// <param name="len">
	/// Input: Total length of buff, in bytes
	/// Output: Length of serialized data, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int Serialize(uint8_t *buff, size_t &len) = 0;

	/// <summary>
	/// Deserializes the extension from binary form,
	/// as it would appear in a PF_KEY_V2 message
	/// </summary>
	/// <param name="data">Binary data</param>
	/// <param name="len">
	/// Input: Total length of data, in bytes
	/// Output: Amount of data consumed, in bytes
	/// </param>
	virtual int Deserialize(const uint8_t *data, size_t &len) = 0;

	/// <summary>
	/// Returns the length of the extension
	/// if it were serialized in its current state
	/// </summary>
	/// <returns>Length, in bytes</returns>
	virtual size_t GetLengthBytes() = 0;

	/// <summary>
	/// Returns the extension type
	/// </summary>
	/// <returns>Extension type</returns>
	/// <remarks>
	/// Values are defined in RFC 2367
	/// </remarks>
	virtual uint16_t GetType() = 0;

	/// <summary>
	/// Returns true if the current state of
	/// this extension object represents a
	/// valid extension
	/// </summary>
	/// <returns>True if valid</returns>
	virtual bool IsValid() = 0;
};

#endif
