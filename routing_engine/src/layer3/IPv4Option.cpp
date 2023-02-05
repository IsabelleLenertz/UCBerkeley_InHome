#include "layer3/IPv4Option.hpp"

ipv4_option_info_t IPv4Option::OptionTable[256]
{
    {true, false},                          // 0 - End of Options List
    {true, false},                          // 1 - No Operation
    {}, {}, {}, {}, {},                     // 2 - 6 (Undefined)
    {true, true},                           // 7 - Record Route
    {}, {},                                 // 8 - 9 (Undefined)
    {false, false},                         // 10 - Experimental Measurement
    {true, true},                           // 11 - MTU Probe
    {true, true},                           // 12 - MTU Reply
    {}, {},                                 // 13 - 14 (Undefined)
    {false, false},                         // 15 - ENCODE (Deprecated)
    {}, {}, {}, {}, {}, {}, {}, {}, {},     // 16 - 24 (Undefined)
    {true, true},                           // 25 - Quick-Start
    {}, {}, {}, {},                         // 26 - 29 (Undefined)
    {false, false},                         // 30 - RFC3692-style Experiment
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 31 - 40 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 41 - 50 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 51 - 60 (Undefined)
    {}, {}, {}, {}, {}, {}, {},             // 61 - 67 (Undefined)
    {true, true},                           // 68 - Timestamp
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 69 - 78 (Undefined)
    {}, {}, {},                             // 79 - 81 (Undefined)
    {true, true},                           // 82 - Traceroute (Deprecated)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 83 - 92 (Undefined)
    {},                                     // 93 (Undefined)
    {false, false},                         // 94 - RFC3692-style Experiment
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 95 - 104 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 105 - 114 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 115 - 124 (Undefined)
    {}, {}, {}, {}, {},                     // 125 - 129 (Undefined)
    {true, true},                           // 130 - Security
    {true, true},                           // 131 - Loose Source Routing
    {},                                     // 132 (Undefined)
    {true, true},                           // 133 - Extended Security
    {true, true},                           // 134 - Commercial Security
    {},                                     // 135 (Undefined)
    {true, true},                           // 136 - Stream ID (Deprecated)
    {true, true},                           // 137 - Strict Source Routing
    {}, {}, {}, {},                         // 138 - 141 (Undefined)
    {false, false},                         // 142 - Experimental Access Control
    {},                                     // 143 (Undefined)
    {false, false},                         // 144 IMI Traffic Descriptor
    {true, true},                           // 145 - Extended Internet Protocol
    {},                                     // 146 (Undefined)
    {true, true},                           // 147 - Address Extension (Deprecated)
    {true, true},                           // 148 - Router Alert
    {true, true},                           // 149 - Selective Directed Broadcast (Deprecated)
    {false, false},                         // 150 - Unassigned
    {false, false},                         // 151 - Dynamic Packet State (Deprecated)
    {false, false},                         // 152 - Upstream Multicast Packet (Deprecated)
    {}, {}, {}, {}, {},                     // 153 - 157 (Undefined)
    {false, false},                         // 158 - RFC3692-style Experiment
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 159 - 168 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 169 - 178 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 179 - 188 (Undefined)
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 189 - 198 (Undefined)
    {}, {}, {}, {}, {}, {},                 // 199 - 204 (Undefined)
    {false, false},                         // 205 - Experimental Flow Control
    {false, false},                         // 222 - RFC3692-style Experiment
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 223 - 232
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 233 - 242
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, // 243 - 252
    {}, {}, {}
};

IPv4Option::IPv4Option()
    : option_type(0),
      data()
{
}

IPv4Option::IPv4Option(uint8_t option_type)
    : option_type(option_type),
      data()
{
}

IPv4Option::IPv4Option(uint8_t option_type, uint8_t len, uint8_t *data)
    : option_type(option_type),
      data(data, data + len)
{
}

IPv4Option::IPv4Option(const IPv4Option& other)
{
    this->option_type = other.option_type;
    this->data = other.data;
}

IPv4Option::~IPv4Option()
{
}

uint8_t IPv4Option::GetOptionType()
{
    return option_type;
}

uint8_t IPv4Option::GetLength()
{
    return (uint8_t)data.size();
}

void IPv4Option::SetData(uint8_t *data_in, uint8_t len)
{
    data = std::vector<uint8_t>(data_in, data_in + len);
}

uint8_t *IPv4Option::GetData()
{
    return data.data();
}