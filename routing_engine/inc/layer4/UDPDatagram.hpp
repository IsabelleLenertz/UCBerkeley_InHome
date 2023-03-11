#ifndef INC_UDPDATAGRAM_HPP_
#define INC_UDPDATAGRAM_HPP_

#include <cstdint>
#include <cstdlib>
#include <vector>

class UDPDatagram
{
public:
	UDPDatagram();
	~UDPDatagram();

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	uint16_t GetSourcePort();
	void SetSourcePort(uint16_t port);

	uint16_t GetDestinationPort();
	void SetDestinationPort(uint16_t port);

	size_t GetLengthBytes();

	const uint8_t *GetData();
	size_t GetDataLength();
	void SetData(const uint8_t *data, size_t len);

private:
	uint16_t _src_port;
	uint16_t _dst_port;
	std::vector<uint8_t> _data;

	const int MIN_DATAGRAM_SIZE_BYTES = 8;
};

#endif
