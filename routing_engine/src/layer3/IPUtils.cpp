#include "layer3/IPUtils.hpp"
#include <cstdint>
#include <cstring>

void IPUtils::GetSubnetID(const struct sockaddr &addr, const struct sockaddr &netmask, struct sockaddr &subnet_id)
{
    switch (addr.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in &_addr = reinterpret_cast<const struct sockaddr_in&>(addr);
            const struct sockaddr_in &_netmask = reinterpret_cast<const struct sockaddr_in&>(netmask);
            struct sockaddr_in &_subnet_id = reinterpret_cast<struct sockaddr_in&>(subnet_id);
            
            _subnet_id.sin_family = AF_INET;
            
            uint32_t *addrptr, *maskptr, *sidptr;
            addrptr = (uint32_t*)&_addr.sin_addr;
            maskptr = (uint32_t*)&_netmask.sin_addr;
            sidptr = (uint32_t*)&_subnet_id.sin_addr;
            
            *sidptr++ = *addrptr++ & *maskptr++;
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 &_addr = reinterpret_cast<const struct sockaddr_in6&>(addr);
            const struct sockaddr_in6 &_netmask = reinterpret_cast<const struct sockaddr_in6&>(netmask);
            struct sockaddr_in6 &_subnet_id = reinterpret_cast<struct sockaddr_in6&>(subnet_id);
            
            _subnet_id.sin6_family = AF_INET6;
            
            uint32_t *addrptr, *maskptr, *sidptr;
            addrptr = (uint32_t*)&_addr.sin6_addr;
            maskptr = (uint32_t*)&_netmask.sin6_addr;
            sidptr = (uint32_t*)&_subnet_id.sin6_addr;
            
            for (int i = 0; i < 4; i++)
            {
                *sidptr++ = *addrptr++ & *maskptr++;
            }
            
            break;
        }
        default:
        {
            break;
        }
    }
}

bool IPUtils::AddressesAreEqual(const struct sockaddr &lhs, const struct sockaddr &rhs)
{
    bool result = true;
    
    if (lhs.sa_family == rhs.sa_family)
    {
        switch (lhs.sa_family)
        {
            case AF_INET:
            {
                const struct sockaddr_in &_lhs = reinterpret_cast<const struct sockaddr_in&>(lhs);
                const struct sockaddr_in &_rhs = reinterpret_cast<const struct sockaddr_in&>(rhs);
                
                result &= (memcmp(&_lhs.sin_addr, &_rhs.sin_addr, 4) == 0);
                break;
            }
            case AF_INET6:
            {
                const struct sockaddr_in6 &_lhs = reinterpret_cast<const struct sockaddr_in6&>(lhs);
                const struct sockaddr_in6 &_rhs = reinterpret_cast<const struct sockaddr_in6&>(rhs);
                
                result &= (memcmp(&_lhs.sin6_addr, &_rhs.sin6_addr, 16) == 0);
                break;
            }
            default:
            {
                result = false;
                break;
            }
        }
    }
    else
    {
        result = false;
    }
    
    return result;
}

void IPUtils::StoreSockaddr(const struct sockaddr &src, struct sockaddr_storage &dst)
{
    switch (src.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in &_src = reinterpret_cast<const struct sockaddr_in&>(src);
            struct sockaddr_in &_dst = reinterpret_cast<struct sockaddr_in&>(dst);
            
            _dst.sin_family = AF_INET;
            _dst.sin_port = _src.sin_port;
            memcpy(&_dst.sin_addr, &_src.sin_addr, 4);
            break;
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 &_src = reinterpret_cast<const struct sockaddr_in6&>(src);
            struct sockaddr_in6 &_dst = reinterpret_cast<struct sockaddr_in6&>(dst);
            
            _dst.sin6_family = AF_INET6;
            _dst.sin6_port = _src.sin6_port;
            _dst.sin6_flowinfo = _src.sin6_flowinfo;
            memcpy(&_dst.sin6_addr, &_src.sin6_addr, 16);
            break;
        }
        default:
        {
            break;
        }
    }
}
