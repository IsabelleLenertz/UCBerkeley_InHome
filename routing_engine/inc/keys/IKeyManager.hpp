#ifndef INC_IKEYMANAGER_HPP_
#define INC_IKEYMANAGER_HPP_

#include <arpa/inet.h>
#include <vector>

class IKeyManager
{
public:
	virtual ~IKeyManager() {};

	/// <summary>
	/// Gets the key data associated with the
	/// specified SPI, source address, and
	/// destination address
	/// </summary>
	/// <param name="spi">Security parameters index</param>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="key">Key data out</param>
	/// <param name="keylen">
	/// Input: Length of key output buffer, in bytes
	/// Output: Length of key data, in bytes
	/// </param>
	/// <returns>Error code</returns>
	virtual int GetKey(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint8_t *key, size_t &keylen) = 0;

	/// <summary>
	/// Gets the SPI associated with the specified
	/// source/destination address. Security association
	/// type is assumed to be Authentication Header
	/// </summary>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="spi">Security parameters index out<param>
	/// <returns>Error code</returns>
	virtual int GetSPI(const sockaddr &src, const sockaddr &dst, uint32_t &spi) = 0;

	/// <summary>
	/// Gets the current replay context associated
	/// with the specified SPI, source address,
	/// and destination address
	/// </summary>
	/// <param name="spi">Security parameters index</param>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="right">Right edge of replay window out</param>
	/// <param name="map">Bitmap of received values out</param>
	/// <returns>Error code</returns>
	/// <remarks>
	/// The right edge of the replay window is equal to the
	/// greatest validated sequence number, UNLESS the greatest
	/// validated sequence number is less than 32
	/// The MSB in the bitmap represents the right edge of
	/// the replay window, with each lesser bit representing
	/// the next highest sequence number. The LSB represents
	/// the left edge of the replay window, equal to the greatest
	/// validated sequence number, minus 32
	/// </remarks>
	virtual int GetReplayContext(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t &right, uint32_t &map) = 0;

	/// <summary>
	/// Marks the specified sequence number as received and
	/// validated for the specified security association
	/// </summary>
	/// <param name="spi">Security parameters index</param>
	/// <param name="src">Source address</param>
	/// <param name="dst">Destination address</param>
	/// <param name="seq_num">Sequence number</param>
	virtual int MarkSequenceNumber(uint32_t spi, const sockaddr &src, const sockaddr &dst, uint32_t seq_num) = 0;
};

#endif /* INC_KEYS_IKEYMANAGER_HPP_ */
