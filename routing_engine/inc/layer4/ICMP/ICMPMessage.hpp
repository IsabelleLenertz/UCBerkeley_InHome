#ifndef INC_ICMPMessage_HPP_
#define INC_ICMPMessage_HPP_

#include <cstdint>
#include <cstdlib>
#include <vector>

#define ICMP_TYPE_REQUEST 8
#define ICMP_TYPE_REPLY 0

class ICMPMessage
{
public:
	ICMPMessage();
	~ICMPMessage();

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	uint8_t GetType();
	void SetType(uint8_t type);

	uint8_t GetCode();

	uint16_t GetID();
	void SetID(uint16_t id);

	uint16_t GetSequenceNumber();
	void SetSequenceNumber(uint16_t num);

	const uint8_t *GetData();
	size_t GetDataLength();
	void SetData(const uint8_t *data, size_t len);

private:
	uint16_t _id;
	uint16_t _seq_num;
	uint8_t _type;
	std::vector<uint8_t> _data;

	static const int MIN_LEN_BYTES = 8;
};

#endif
