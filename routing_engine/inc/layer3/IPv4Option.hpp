#ifndef IPV4_OPTION_H_
#define IPV4_OPTION_H_

#include <cstdint>
#include <vector>

// Indicates whether a particular IPv4 option type
// is defined, and whether it includes a length byte
// This is necessary to parse incoming packet options
typedef struct
{
    bool defined : 1;
    bool varlen : 1;
} ipv4_option_info_t;

class IPv4Option
{
public:
    static ipv4_option_info_t OptionTable[256];

    /// <summary>
    /// Default constructor
    /// </summary>
    IPv4Option();
    
    /// <summary>
    /// Constructs an IPv4 option without
    /// a data segment
    /// </summary>
    IPv4Option(uint8_t option_type);
    
    /// <summary>
    /// Constructs an IPv4 option with
    /// a data segment
    /// </summary>
    IPv4Option(uint8_t option_type, uint8_t len, uint8_t *data);
    
    /// <summary>
    /// Copy constructor
    /// </summary>
    IPv4Option(const IPv4Option& other);
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~IPv4Option();
    
    /// <summary>
    /// Returns the option type
    /// </summary>
    /// <returns>Option type</returns>
    uint8_t GetOptionType();
    
    /// <summary>
    /// Gets the length of the data segment
    /// </summary>
    /// <returns>Length of data segment, in bytes</returns>
    /// <remarks>
    /// Returned value does not include option type and length bytes
    /// </remarks>
    uint8_t GetLength();
    
    /// <summary>
    /// Gets a pointer to the data segment
    /// </summary>
    /// <returns>Pointer to data</returns>
    uint8_t* GetData();
    
    /// <summary>
    /// Sets the data segment
    /// </summary>
    /// <param name="data">Data</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <remarks>
    /// Length value does not include option type and length bytes
    /// </remarks>
    void SetData(uint8_t *data_in, uint8_t len);
    
private:
    uint8_t option_type;
    std::vector<uint8_t> data;
};

#endif