#ifndef INC_TCPSEGMENT_HPP_
#define INC_TCPSEGMENT_HPP_

#include <cstdint>
#include <cstdlib>
#include <vector>

class TCPSegment
{
public:
	TCPSegment();
	~TCPSegment();

	int Serialize(uint8_t *buff, size_t &len);
	int Deserialize(const uint8_t *data, size_t len);

	uint16_t GetSourcePort();
	void SetSourcePort(uint16_t port);

	uint16_t GetDestinationPort();
	void SetDestinationPort(uint16_t port);

	uint32_t GetSequenceNumber();
	void SetSequenceNumber(uint32_t num);

	uint32_t GetAckNumber();
	void SetAckNumber(uint32_t num);

	size_t GetHeaderLengthBytes();

	bool GetURG();
	void SetURG(bool urg);

	bool GetACK();
	void SetACK(bool ack);

	bool GetPSH();
	void SetPSH(bool psh);

	bool GetRST();
	void SetRST(bool rst);

	bool GetSYN();
	void SetSYN(bool syn);

	bool GetFIN();
	void SetFIN(bool fin);

	uint16_t GetWindow();
	void SetWindow(uint16_t window);

	uint16_t GetUrgentPtr();
	void SetUrgentPtr(uint16_t ptr);

	const uint8_t *GetData();
	size_t GetDataLength();
	void SetData(const uint8_t *data, size_t len);

private:
	uint16_t _src_port;
	uint16_t _dst_port;
	uint32_t _seq_num;
	uint32_t _ack_num;
	bool _urg;
	bool _ack;
	bool _psh;
	bool _rst;
	bool _syn;
	bool _fin;
	uint16_t _window;
	uint16_t _urgent_ptr;
	std::vector<uint8_t> _opts;
	std::vector<uint8_t> _data;

	const int MIN_HEADER_LEN_BYTES = 20;
	const int MAX_HEADER_LEN_BYTES = 60;
};

#endif
