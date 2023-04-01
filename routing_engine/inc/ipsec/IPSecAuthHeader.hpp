#ifndef INC_IPSECAUTHHEADER_HPP_
#define INC_IPSECAUTHHEADER_HPP_

#include <cstdint>
#include <cstdlib>
#include <vector>

class IPSecAuthHeader
{
public:
	IPSecAuthHeader();
	~IPSecAuthHeader();

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t &len);

	uint8_t GetNextHeader();
	void SetNextHeader(uint8_t next);

	/// <summary>
	/// Gets the length of the authentication
	/// header in its current state, in bytes
	/// </summary>
	/// <returns>Length, in bytes</returns>
	uint8_t GetLengthBytes();

	uint32_t GetSPI();
	void SetSPI(uint32_t spi);

	uint32_t GetSequenceNumber();
	void SetSequenceNumber(uint32_t num);

	size_t GetICV(const uint8_t* &data);
	void SetICV(const uint8_t *data, size_t len);

private:
	uint8_t _next_hdr;
	uint8_t _payload_len;
	uint32_t _spi;
	uint32_t _seq_num;

	std::vector<uint8_t> _icv;

	const size_t AH_MIN_LEN_BYTES = 12;
};



#endif
