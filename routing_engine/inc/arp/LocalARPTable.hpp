#ifndef INC_LOCALARPTABLE_HPP_
#define INC_LOCALARPTABLE_HPP_

#include "arp/IARPTable.hpp"
#include <vector>
#include <cstdint>
#include <mutex>

/// <summary>
/// Stores a mapping between a layer 2
/// address and an IPv4 address
/// </summary>
/// <remarks>
/// The l3_addr data member is essentially
/// the same as the sa_data member of
/// the sockaddr structure defined in
/// sys/socket.h, specialized for IPv4
/// </remarks>
typedef struct
{
    struct ether_addr l2_addr;
    uint8_t l3_addr[4];
} ARPv4Entry_t;

/// <summary>
/// Stores a mapping between a layer 2
/// address and an IPv6 address
/// </summary>
/// <remarks>
/// The l3_addr data member is essentially
/// the same as the sa_data member of
/// the sockaddr structure defined in
/// sys/socket.h, specialized for IPv6
/// </remarks>
typedef struct
{
    struct ether_addr l2_addr;
    uint8_t l3_addr[16];
} ARPv6Entry_t;

/// <summary>
/// Concrete implementation of IARPTable
/// which stores ARP table entries in local
/// process memory
/// <summary>
class LocalARPTable : public IARPTable
{
public:
    /// <summary>
    /// Default constructor
    /// </summary>
    LocalARPTable();
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~LocalARPTable();
    
    void SetARPEntry(const struct sockaddr &l3_addr, const struct ether_addr &l2_addr);
    bool GetL2Address(const struct sockaddr &l3_addr, struct ether_addr& l2_addr);

private:
    std::vector<ARPv4Entry_t> _v4table;
    std::vector<ARPv6Entry_t> _v6table;
    
    std::mutex _mutex;
};

#endif
