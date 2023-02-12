#include "layer3/IPv4Packet.hpp"

#include <arpa/inet.h>
#include <cstring>

IPv4Packet::IPv4Packet()
    : _tos(0),
      _stream_id(0),
      _dont_fragment(false),
      _more_fragments(false),
      _fragment_offset(0),
      _ttl(0),
      _protocol(0),
      _source_addr(0),
      _dest_addr(0),
      _options(),
      _data()
{
}

IPv4Packet::~IPv4Packet()
{
}

int IPv4Packet::GetIPVersion()
{
    return 4;
}

int IPv4Packet::Deserialize(const uint8_t *buff, uint16_t len)
{
    const uint8_t *ptr = buff;
    uint32_t tmp;
    
    // If the first word can't be formed, return overflow error
    if (len < sizeof(uint32_t))
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Converting to uint32_t makes bitwise manipulation easier
    // Get first word
    tmp = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);
    
    // Verify that the IP version is 4
    uint8_t version = (uint8_t)((tmp >> 4) & 0xF);
    if (version != 4)
    {
        return IPV4_PACKET_ERROR_INVALID_VERSION;
    }
    
    // Get Header Length, convert to bytes
    uint8_t header_len = (tmp & 0xF) * sizeof(uint32_t);
    
    // Get TOS
    _tos = (uint8_t)((tmp >> 8) & 0xF);
    
    // Get Total Length
    uint16_t total_len = (tmp >> 16);
    total_len = ntohs(total_len);
    
    // Verify enough data is in the packet
    // for specified total length
    if (len < total_len)
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Get second word
    tmp = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);
    
    // Get Stream ID
    _stream_id = (uint16_t)(tmp & 0xFFFF);
    _stream_id = ntohs(_stream_id);
    
    // Get Don't Fragment Flag
    _dont_fragment = (bool)((tmp >> 22) & 0x1);
    
    // Get More Fragments Flag
    _more_fragments = (bool)((tmp >> 21) & 0x1);
    
    // Get Fragment Offset
    _fragment_offset = (uint16_t)(tmp >> 16);
    _fragment_offset = ntohs(_fragment_offset);
    _fragment_offset &= 0x1FFF; // Remove flag bits
    
    // Get third word
    tmp = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);
    
    // Get Time-to-Live (TTL)
    _ttl = (uint8_t)(tmp & 0xFF);
    
    // Get Protocol
    _protocol = (uint8_t)((tmp >> 8) & 0xFF);
    
    //////// Validate Checksum ////////
    
    // Calculate checksum
    uint16_t checksum_calculated = CalcHeaderChecksum(buff, header_len);
    
    // Checksum of header (including checksum bytes)
    // must be 0
    if (checksum_calculated != 0)
    {
        return IPV4_PACKET_ERROR_INVALID_CHECKSUM;
    }
    
    // Extract Source Address
    tmp = ntohl(*(uint32_t*)ptr);
    _source_addr = *(in_addr_t*)&tmp;
    ptr += sizeof(in_addr_t);
    
    // Extract Destination Address
    tmp = ntohl(*(uint32_t*)ptr);
    _dest_addr = *(in_addr_t*)&tmp;
    ptr += sizeof(in_addr_t);
    
    // Parse options to the end of the header
    uint8_t option_type, option_len;
    while (ptr - buff < header_len) // (ptr - buff) is the byte offset from the start of the buffer
    {
        option_len = 0;
        option_type = *ptr++;
        
        // Check for End of Options byte/padding
        if (option_type == 0)
        {
            continue;
        }
        
        // Check for an undefined option type
        if (!IPv4Option::OptionTable[option_type].defined)
        {
            return IPV4_PACKET_ERROR_UNDEFINED_OPTION;
        }
        
        // Check if this is a variable-length option
        if (IPv4Option::OptionTable[option_type].varlen)
        {
            // Get length byte
            option_len = *ptr++;
            option_len -= 2; // Don't include option type and length bytes
            
            // Add variable-length option
            _options.push_back(IPv4Option(option_type, option_len, ptr));
            
            // Advance pointer
            ptr += option_len;
        }
        else
        {
            // Add single-byte option
            _options.push_back(IPv4Option(option_type));
        }
    }
    
    // Calculate payload length
    uint16_t payload_len = total_len - header_len;
    
    // Copy data payload
    _data = std::vector<uint8_t>(ptr, ptr + payload_len);
    
    return IPV4_PACKET_SUCCESS;
}

int IPv4Packet::Serialize(uint8_t* buff, uint16_t& len)
{
    uint8_t *ptr = buff;
    uint32_t tmp;
    
    // Construct word 0
    tmp = 0x40; // Version (always 4)
    tmp |= (uint32_t)(GetHeaderLengthBytes() / sizeof(uint32_t));
    tmp |= ((uint32_t)_tos) << 8;
    tmp |= ((uint32_t)htons(GetTotalLengthBytes())) << 16;
    
    // Write word 0
    *(uint32_t*)ptr = tmp;
    ptr += sizeof(uint32_t);
    
    // Construct word 1
    tmp = (uint32_t)htons(_stream_id);
    tmp |= ((uint32_t)_more_fragments) << 21;
    tmp |= ((uint32_t)_dont_fragment) << 22;
    tmp |= ((uint32_t)htons(_fragment_offset)) << 16;
    
    // Write word 1
    *(uint32_t*)ptr = tmp;
    ptr += sizeof(uint32_t);
    
    // Write word 2 (except checksum)
    tmp = (uint32_t)(_ttl);
    tmp |= ((uint32_t)_protocol) << 8;
    *(uint32_t*)ptr = tmp;
    ptr += sizeof(uint32_t);
    
    // Write Source Address
    tmp = *(uint32_t*)&_source_addr;
    *(uint32_t*)ptr = htonl(tmp);
    ptr += sizeof(in_addr_t);
    
    // Write Destination Address
    tmp = *(uint32_t*)&_dest_addr;
    *(uint32_t*)ptr = htonl(tmp);
    ptr += sizeof(in_addr_t);
    
    // Write options
    for (auto opt = _options.begin(); opt < _options.end(); opt++)
    {
        IPv4Option& option = *opt;
        
        // Write Option Type
        *ptr++ = option.GetOptionType();
        
        // Cannot serialize unknown option type
        if (!IPv4Option::OptionTable[option.GetOptionType()].defined)
        {
            return IPV4_PACKET_ERROR_UNDEFINED_OPTION;
        }
        
        // If variable length, write length and data
        if (IPv4Option::OptionTable[option.GetOptionType()].varlen)
        {
            // Write length byte (length is +2 because it
            // includes option type and length byte
            *ptr++ = option.GetLength() + 2;
            
            memcpy(ptr, option.GetData(), option.GetLength());
            ptr += option.GetLength();
        }
    }
    
    // Write padding
    uint8_t header_len = GetHeaderLengthBytes();
    while (ptr - buff < header_len)
    {
        *ptr++ = 0;
    }
    
    // Calculate Header Checksum
    uint16_t checksum = CalcHeaderChecksum(buff, GetHeaderLengthBytes());
    
    // Write checksum to header
    *(uint16_t*)(buff + 10) = checksum;
    
    // Write data payload
    memcpy(ptr, _data.data(), _data.size());
    
    len = GetTotalLengthBytes();
    
    return IPV4_PACKET_SUCCESS;
}

// Read-only
uint8_t IPv4Packet::GetHeaderLengthBytes()
{
    // Begin with fixed header size
    int num_bytes = MIN_HEADER_SIZE_BYTES;
    
    // Parse through options
    for (auto opt = _options.begin(); opt < _options.end(); opt++)
    {
        IPv4Option& option = *opt;
        
        // Advance one byte for option type
        num_bytes++;
        
        // If variable length
        if (IPv4Option::OptionTable[option.GetOptionType()].varlen)
        {
            // Advance one byte for length byte
            num_bytes++;
            
            // Advance by length of data portion
            num_bytes += option.GetLength();
        }
    }
    
    // Round up to nearest 32-bit boundary
    return (((num_bytes - 1) / sizeof(uint32_t)) + 1) * sizeof(uint32_t);
}

uint16_t IPv4Packet::GetTotalLengthBytes()
{
    return GetHeaderLengthBytes() + _data.size();
}

// Read/write
uint8_t IPv4Packet::GetTOS()
{
    return _tos;
}

void IPv4Packet::SetTOS(uint8_t tos)
{
    _tos = tos;
}

uint16_t IPv4Packet::GetStreamID()
{
    return _stream_id;
}

void IPv4Packet::SetStreamID(uint16_t sid)
{
    _stream_id = sid;
}

bool IPv4Packet::GetDontFragment()
{
    return _dont_fragment;
}

void IPv4Packet::SetDontFragment(bool df)
{
    _dont_fragment = df;
}

bool IPv4Packet::GetMoreFragments()
{
    return _more_fragments;
}

void IPv4Packet::SetMoreFragments(bool mf)
{
    _more_fragments = mf;
}

uint16_t IPv4Packet::GetFragmentOffset()
{
    return _fragment_offset;
}

void IPv4Packet::SetFragmentOffset(uint16_t offset)
{
    _fragment_offset = offset & 0x1FFF;
}

uint8_t IPv4Packet::GetTTL()
{
    return _ttl;
}

void IPv4Packet::SetTTL(uint8_t ttl)
{
    _ttl = ttl;
}

uint8_t IPv4Packet::GetProtocol()
{
    return _protocol;
}

void IPv4Packet::SetProtocol(uint8_t proto)
{
    _protocol = proto;
}

in_addr_t IPv4Packet::GetSourceAddress()
{
    return _source_addr;
}

void IPv4Packet::SetSourceAddress(in_addr_t addr)
{
    _source_addr = addr;
}

in_addr_t IPv4Packet::GetDestinationAddress()
{
    return _dest_addr;
}

void IPv4Packet::SetDestinationAddress(in_addr_t addr)
{
    _dest_addr = addr;
}

// Options
IPv4Option* IPv4Packet::GetOption(uint8_t option_type)
{
    for (auto opt = _options.begin(); opt < _options.end(); opt++)
    {
        if ((*opt).GetOptionType() == option_type)
        {
            return &(*opt);
        }
    }
    
    return nullptr;
}

void IPv4Packet::SetOption(uint8_t option_type, uint8_t len, uint8_t* data_in)
{
    IPv4Option *opt = GetOption(option_type);
    if (opt != nullptr)
    {
        // If option already exists, overwrite data
        if (data_in != nullptr)
        {
            // if data was provided, overwrite data
            opt->SetData(data_in, len);
        }
    }
    else
    {
        if (data_in != nullptr)
        {
            // If data was provided, add a new option with data
            _options.push_back(IPv4Option(option_type, len, data_in));
        }
        else
        {
            // If data was not provided, new single-byte option
            _options.push_back(IPv4Option(option_type));
        }
    }
}

void IPv4Packet::RemoveOption(uint8_t option_type)
{
    for (auto opt = _options.begin(); opt < _options.end(); opt++)
    {
        if ((*opt).GetOptionType() == option_type)
        {
            _options.erase(opt);
            break;
        }
    }
}

void IPv4Packet::SetData(uint8_t *data_in, uint16_t len)
{
    _data = std::vector<uint8_t>(data_in, data_in + len);
}

uint16_t IPv4Packet::GetData(const uint8_t* &data_out)
{
    data_out = _data.data();
    return _data.size();
}

uint16_t IPv4Packet::CalcHeaderChecksum(const uint8_t *buff, size_t len)
{
    if (len % 2 != 0)
    {
        return 0;
    }

    uint32_t result = 0;
    uint32_t offset = 0;
    
    for (offset = 0; offset < len; offset += 2)
    {
        result += *(uint16_t*)(buff + offset);
    }

    uint16_t carry = (uint16_t)(result >> 16);
    result += carry;

    return ~(uint16_t)result;
}
