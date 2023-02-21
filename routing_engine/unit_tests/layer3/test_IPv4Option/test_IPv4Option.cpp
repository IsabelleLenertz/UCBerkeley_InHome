#include "gtest/gtest.h"
#include "layer3/IPv4Option.hpp"
#include <cstring>

/// <summary>
/// Creates an IPv4Option object with
/// a single byte (option_type) and
/// validates that value
/// </summary>
TEST(test_IPv4Option, test_single_byte)
{
    static const int OPTION_TYPE = 1; // 1 is No Operation
    IPv4Option opt(OPTION_TYPE);
    
    // Verify that the option type is defined
    ASSERT_EQ(true, IPv4Option::OptionTable[OPTION_TYPE].defined);
    
    // Verify that the option type is single-byte
    ASSERT_EQ(false, IPv4Option::OptionTable[OPTION_TYPE].varlen);
    
    // Verify Option Type returns correctly
    ASSERT_EQ(OPTION_TYPE, opt.GetOptionType());
    
    // Verify Length is correct (0)
    ASSERT_EQ(0, opt.GetLength());
    
    // Verify data is correctly initialized to nullptr
    ASSERT_EQ(nullptr, opt.GetData());
}

/// <summary>
/// Creates an IPv4Option object with
/// variable length and validates the
/// option type, length, and data
/// </summary>
TEST(test_IPv4Option, test_variable_length)
{
    static const int OPTION_TYPE = 130; // 130 is Security
    static const int OPTION_LEN = 4;
    static const uint8_t OPTION_DATA[OPTION_LEN]
                       = {0xAA, 0xBB, 0xCC, 0xDD};
    
    IPv4Option opt(OPTION_TYPE, OPTION_LEN, OPTION_DATA);
    
    // Verify that the option type is defined
    ASSERT_EQ(true, IPv4Option::OptionTable[OPTION_TYPE].defined);
    
    // Verify that the option type is variable-length
    ASSERT_EQ(true, IPv4Option::OptionTable[OPTION_TYPE].varlen);
    
    // Verify Option Type returns correctly
    ASSERT_EQ(OPTION_TYPE, opt.GetOptionType());
    
    // Verify length is correct
    ASSERT_EQ(OPTION_LEN, opt.GetLength());
    
    // Verify data is correct
    ASSERT_EQ(0, memcmp(OPTION_DATA, opt.GetData(), OPTION_LEN));
}
