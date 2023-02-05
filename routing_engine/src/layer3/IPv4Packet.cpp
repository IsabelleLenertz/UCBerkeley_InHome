#include "layer3/IPv4Packet.hpp"
#include <arpa/inet>

IPv4Packet::IPv4Packet()
    : word0(),
      word1(),
      word2(),
      source_addr(0),
      dest_addr(0),
      options(),
      data()
{
}

IPv4Packet::~IPv4Packet()
{
}

int IPv4Packet::Deserialize(uint8_t *buff, uint16_t len)
{
    uint8_t *ptr = buff;
    
    // If the first word can't be formed, return overflow error
    if (len < sizeof(uint32_t))
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Extract word 0: Header Length, TOS, Total Length
    word0 = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);
    
    // Convert header length from words to bytes
    uint8_t header_len = word0.header_len * sizeof(uint32_t);
    
    // Validate that the amount of data in the buffer is enough to
    // hold the specified total packet length
    if (len < word0.total_len)
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Extract word 1: Stream ID, Flags, Fragment Offset
    word1 = ntohl(*(uint32_t*)ptr);
    ptr += sizeof(uint32_t);
    
    // Extract word 2: TTL, Header Checksum
    word2 = ntohl(*(uint32_t*)ptr);
    
    //////// Validate Checksum ////////
    // Zero-Out checksum from buffer
    *((uint32_t*)ptr) &= 0x0000FFFF;
    
    // Calculate checksum
    uint16_t checksum_calculated = CalcHeaderChecksum(buff, header_len);
    if (checksum_calculated != word2.checksum)
    {
        return IPV4_PACKET_ERROR_INVALID_CHECKSUM;
    }
    
    // Restore checksum
    *((uint32_t*)ptr) = htonl(word2); // TODO Validate this
    
    ptr += sizeof(uint32_t);
    
    // Extract Source Address
    source_addr = *(in_addr_t*)ptr;
    ptr += sizeof(in_addr_t);
    
    // Extract Destination Address
    dest_addr = *(in_addr_t*)ptr;
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
        if (!IPv4OptionInfoTable[option_type].defined)
        {
            return IPV4_PACKET_ERROR_UNDEFINED_OPTION;
        }
        
        // Check if this is a variable-length option
        if (IPv4OptionInfoTable[option_type].varlen)
        {
            // Get length byte
            option_len = *ptr++;
            
            // Add variable-length option
            options.push_back(IPv4Option(option_type, option_len, ptr));
            
            // Advance pointer
            ptr += option_len;
        }
        else
        {
            // Add single-byte option
            options.push_back(IPv4Option(option_type));
        }
    }
    
    // Calculate payload length
    uint16_t payload_len = word0.total_len - header_len;
    
    // Copy data payload
    data = std::vector<uint8_t>(ptr, ptr + payload_len);
    
    return IPV4_PACKET_ERROR_NO_ERROR;
}

int IPv4Packet::Serialize(uint8_t* buff, uint16_t& len)
{
    uint8_t *ptr = buff;
    
    // Verify that the buffer length can store packet data
    if (len < GetTotalLengthBytes())
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Verify that the header is not too big
    if (GetHeaderLengthBytes() > MAX_HEADER_LEN_BYTES)
    {
        return IPV4_PACKET_ERROR_OVERFLOW;
    }
    
    // Write word 0
    word0.version = 4; // IPv4
    word0.header_len = GetHeaderLengthBytes() / sizeof(uint32_t);
    word0.total_len = GetTotalLengthBytes();
    *((uint32_t*)ptr) = htonl(word0);
    ptr += sizeof(uint32_t);
    
    // Write word 1
    *((uint32_t*)ptr) = htonl(word1);
    ptr += sizeof(uint32_t);
    
    // Write word 2
    word2.checksum = 0;
    *((uint32_t*)ptr) = htonl(word2);
    ptr += sizeof(uint32_t);
    
    // Write Source Address
    *((in_addr_t*)ptr) = source_addr;
    ptr += sizeof(in_addr_t);
    
    // Write Destination Address
    *((in_addr_t*)ptr) = dest_addr;
    ptr += sizeof(in_addr_t);
    
    // Calculate and populate checksum
    word2.checksum = CalcHeaderChecksum(buff, GetHeaderLengthBytes());
    *((uint32_t*)(buff + 16)) = htonl(word2);
    
    // Write options
    for (auto opt = options.begin(); opt < options.end(); opt++)
    {
        IPv4Option& option = *opt;
        
        // Write Option Type
        *ptr++ = option.GetOptionType();
        
        // Cannot serialize unknown option type
        if (!IPv4OptionTable[option.GetOptionType].defined)
        {
            return IPV4_PACKET_ERROR_UNDEFINED_OPTION;
        }
        
        // If variable length, write length and data
        if (IPv4OptionInfoTable[option.GetOptionType()].varlen)
        {
            *ptr++ = option.GetLength();
            
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
    
    // Write data payload
    memcpy(ptr, data.data(), data.size());
    
    len = word0.total_len;
    
    return IPV4_PACKET_ERROR_NO_ERROR;
}

// Read-only
uint8_t IPv4Packet::GetHeaderLengthBytes()
{
    // Begin with fixed header size
    int num_bytes = MIN_HEADER_SIZE_BYTES;
    
    // Parse through options
    for (auto opt = options.begin(); opt < options.end(); opt++)
    {
        IPv4Option& option = *opt;
        
        // Advance one byte for option type
        num_bytes++;
        
        // If variable length
        if (IPv4OptionInfoTable[option.GetOptionType()].varlen)
        {
            // Advance one byte for length byte
            num_bytes++;
            
            // Advance by length of data portion
            num_bytes += option.GetLength();
        }
    }
    
    // Round up to nearest 32-bit boundary
    return (((num_bytes - 1) / sizeof(uint32_t)) + 1;
}

uint16_t IPv4Packet::GetTotalLengthBytes()
{
    return GetHeaderLengthBytes() + data.size();
}

// Read/write
uint8_t IPv4Packet::GetTOS()
{
    return word0.tos;
}

void IPv4Packet::SetTOS(uint8_t tos)
{
    word0.tos = tos;
}

uint16_t IPv4Packet::GetStreamID()
{
    return word1.stream_id;
}

void IPv4Packet::SetStreamID(uint16_t sid)
{
    word1.stream_id = sid;
}

bool IPv4Packet::GetDontFragment()
{
    return word1.dont_fragment;
}

void IPv4Packet::SetDontFragment(bool df)
{
    word1.dont_fragment = df;
}

bool IPv4Packet::GetMoreFragments()
{
    return word1.more_fragments;
}

void IPv4Packet::SetMoreFragments(bool mf)
{
    word1.more_fragments = mf;
}

uint16_t IPv4Packet::GetFragmentOffset()
{
    return word1.fragment_offset;
}

void IPv4Packet::SetFragmentOffset(uint16_t offset)
{
    word1.fragment_offset = offset;
}

in_addr_t IPv4Packet::GetSourceAddress()
{
    return source_addr;
}

void IPv4Packet::SetSourceAddress(in_addr_t addr)
{
    source_addr = addr;
}

in_addr_t IPv4Packet::GetDestinationAddress()
{
    return dest_addr;
}

void IPv4Packet::SetDestinationAddress(in_addr_t addr)
{
    dest_addr = addr;
}

// Options
IPv4Option* IPv4Packet::GetOption(uint8_t option_type)
{
    for (auto opt = options.begin(); opt < options.end(); opt++)
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
            options.push_back(IPv4Option(option_type, len, data_in));
        }
        else
        {
            // If data was not provided, new single-byte option
            options.push_back(IPv4Option(option_type));
        }
    }
}

void IPv4Packet::RemoveOption(uint8_t option_type)
{
    for (auto opt = options.begin(); opt < options.end(); opt++)
    {
        if ((*opt).GetOptionType() == option_type)
        {
            options.erase(opt);
            break;
        }
    }
}

void IPv4Packet::SetData(uint8_t *data_in, uint16_t len)
{
    data = std::vector<uint8_t>(data_in, data_in + len);
}

uint16_t IPv4Packet::GetData(uint8_t *data_out)
{
    data_out = data.data();
    return data.size();
}

uint16_t IPv4Packet::CalcHeaderChecksum(uint8_t *buff, size_t len)
{
    // Cannot calculate if buffer is not 16-bit aligned
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
    
    return ~(uint16_t)ntohs(result);
}