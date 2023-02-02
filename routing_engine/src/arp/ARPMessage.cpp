#include "arp/ARPMessage.hpp"

ARPMessage::ARPMessage()
    : _hw_type(ARP_HW_TYPE_ETHERNET),
      _proto_type(ARP_PROTO_TYPE_IPV4),
      _msg_type(ARP_MSG_TYPE_REQUEST),
      _hw_addr_len(6),
      _proto_addr_len(4),
      _src_hw_addr(nullptr),
      _src_proto_addr(nullptr),
      _targ_hw_addr(nullptr),
      _targ_proto_addr(nullptr)
{
}

ARPMessage::~ARPMessage()
{
    if (_src_hw_addr != nullptr)
    {
        delete _src_hw_addr;
    }
    if (_src_proto_addr != nullptr)
    {
        delete _src_proto_addr;
    }
    if (_targ_hw_addr != nullptr)
    {
        delete _targ_hw_addr;
    }
    if (_targ_proto_addr != nullptr)
    {
        delete _targ_proto_addr;
    }
}

int ARPMessage::Deserialize(const uint8_t *data, size_t len)
{
    if (len < MIN_SIZE_BYTES)
    {
        return 1; // Overflow Error
    }
    
    uint8_t *ptr = data;
    
    // Get hardware type
    _hw_type = (arp_hw_type_t) *(uint16_t*)ptr;
    ptr += sizeof(uint16_t); // Advance 2 bytes
    
    // Get protocol type
    _proto_type = (arp_proto_type_t) *(uint16_t*)ptr;
    ptr += sizeof(uint16_t); // Advance 2 bytes
    
    // Get HW address length byte
    _hw_addr_len = *ptr++;
    
    // Get protocol address length byte
    _proto_addr_len = *ptr++;
    
    // Get message type (OpCode)
    _msg_type = (arp_msg_type_t) *(uint16_t*)ptr;
    ptr += sizeof(uint16_t);
    
    // Calculate expected number of bytes remaining
    int bytes_remaining = (_hw_addr_len * 2) + (_proto_addr_len * 2);
    
    // Verify the amount of data remaining
    if (len - (ptr - data)  < bytes_remaining)
    {
        return 1; // Overflow Error
    }
    
    // Get sender HW address
    _src_hw_addr = new uint8_t[_hw_addr_len];
    memcpy(_src_hw_addr, ptr, _hw_addr_len);
    ptr += _hw_addr_len;
    
    // Get sender protocol address
    _src_proto_addr = new uint8_t[_proto_addr_len];
    memcpy(_src_proto_addr, ptr, _proto_addr_len);
    ptr += _proto_addr_len;
    
    // Get target HW address
    _targ_hw_addr = new uint8_t[_hw_addr_len];
    memcpy(_targ_hw_addr, ptr, _hw_addr_len);
    ptr += _hw_addr_len;
    
    // Get target protocol address
    _targ_proto_addr = new uint8_t[_proto_addr_len];
    memcpy(_targ_proto_addr, ptr, _proto_addr_len);
    ptr += _proto_addr_len;
    
    return 0;
}

int ARPMessage::Serialize(uint8_t *buff, size_t &len)
{
    // Calculate size of message in bytes
    size_t msg_len = MIN_SIZE_BYTES +
        (_hw_addr_len * 2) + (_proto_addr_len * 2);
    
    // Verify the buffer is big enough for the message
    if (len < msg_len)
    {
        return 1; // Overflow Error
    }
    
    // Verify that all addresses are defined
    if (_src_hw_addr == nullptr || _src_proto_addr == nullptr ||
        _targ_hw_addr == nullptr || _targ_proto_addr == nullptr)
    {
        return 2; // Undefined address
    }
    
    // Set output message length
    len = msg_len;
    
    // Set pointer to start of output buffer
    uint8_t *ptr = buff;
    
    // Set hardware type
    *(uint16_t*)ptr = (uint16_t)_hw_type;
    ptr += sizeof(uint16_t);
    
    // Set protocol type
    *(uint16_t*)ptr = (uint16_t)_proto_type;
    ptr += sizeof(uint16_t);
    
    // Set HW address length
    *ptr++ = _hw_addr_len;
    
    // Set protocol address length
    *ptr++ = _proto_addr_len;
    
    // Set message type (OpCode)
    *(uint16_t*)ptr = (uint16_t)_msg_type;
    ptr += sizeof(uint16_t);
    
    // Set sender HW address
    memcpy(ptr, _src_hw_addr, _hw_addr_len);
    ptr += _hw_addr_len;
    
    // Set sender protocol address
    memcpy(ptr, _src_proto_addr, _proto_addr_len);
    ptr += _proto_addr_len;
    
    // Set target HW address
    memcpy(ptr, _targ_hw_addr, _hw_addr_len);
    ptr += _hw_addr_len;
    
    // Set target protocol address
    memcpy(ptr, _targ_proto_addr, _proto_addr_len);
    
    return 0;
}

arp_hw_type_t ARPMessage::GetHWType()
{
    return _hw_type;
}

void ARPMessage::SetHWType(arp_hw_type_t hw_type)
{
    _hw_type = hw_type;
}

arp_proto_type_t ARPMessage::GetProtocolType()
{
    return _proto_type;
}

void ARPMessage::SetProtocolType(arp_proto_type_t p_type)
{
    _proto_type = p_type;
}

uint8_t ARPMessage::GetHWAddrLen()
{
    return _hw_addr_len;
}

void ARPMessage::SetHWAddrLen(uint8_t len)
{
    _hw_addr_len = len;
}

uint8_t ARPMessage::GetProtoAddrLen()
{
    return _proto_addr_len;
}

void ARPMessage::SetProtoAddrLen(uint8_t len)
{
    _proto_addr_len = len;
}

arp_msg_type_t ARPMessage::GetMessageType()
{
    return _msg_type;
}

void ARPMessage::SetMessageType(arp_msg_type_t type)
{
    _msg_type = type;
}

uint8_t *ARPMessage::GetSenderHWAddr()
{
    return _src_hw_addr;
}

void ARPMessage::SetSenderHWAddress(uint8_t *addr, uint8_t len)
{
    if (_src_hw_addr != nullptr)
    {
        // Deallocate current HW address
        delete _src_hw_addr;
    }
    
    _src_hw_addr = new uint8_t[len];
    memcpy(_src_hw_addr, addr, len);
}

uint8_t *ARPMessage::GetSenderProtoAddress()
{
    return _src_proto_addr;
}

void ARPMessage::SetSenderProtoAddress(uint8_t *addr, uint8_t len)
{
    if (_src_proto_addr != nullptr)
    {
        // Deallocate current protocol address
        delete _src_proto_addr;
    }
    
    _src_proto_addr = new uint8_t[len];
    memcpy(_src_proto_addr, addr, len);
}

uint8_t *ARPMessage::GetTargetHWAddress()
{
    return _targ_hw_addr;
}

void ARPMessage::SetTargetHWAddress(uint8_t *addr, uint8_t len)
{
    if (_targ_hw_addr != nullptr)
    {
        // Deallocate current HW address
        delete _targ_hw_addr;
    }
    
    _targ_hw_addr = new uint8_t[len];
    memcpy(_targ_hw_addr, addr, len);
}

uint8_t *ARPMessage::GetTargetProtoAddress()
{
    return _targ_proto_addr;
}

void ARPMessage::SetTargetProtoAddress(uint8_t *addr, uint8_t len)
{
    if (_targ_proto_addr != nullptr)
    {
        // Deallocate current protocol address
        delete _targ_proto_addr;
    }
    
    _targ_proto_addr = new uint8_t[len];
    memcpy(_targ_hw_addr, addr, len);
}