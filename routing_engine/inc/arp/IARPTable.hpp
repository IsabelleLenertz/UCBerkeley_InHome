#ifndef INC_IARPTABLE_HPP_
#define INC_IARPTABLE_HPP_

#include <netinet/in.h>
#include <net/ethernet.h>

class IARPTable
{
public:
    void SetARPEntry(const in_addr_t &l3_addr, const struct ether_addr &l2_addr);
    struct ether_addr GetL2Address(const in_addr_t &l3_addr);
    in_addr_t GetL3Address(const struct ether_addr &l2_addr);
};

#endif