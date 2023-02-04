#ifndef INC_MYSQLCONFIGURATION_HPP_
#define INC_MYSQLCONFIGURATION_HPP_

#include "config/IConfiguration.hpp"

/// <summary>
/// Concrete implementation of configuration module
/// using a MySQL server
/// </summary>
class MySQLConfiguration : public IConfiguration
{
public:
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="port">Port of MySQL server</param>
    /// <param name="username">MySQL username</param>
    /// <param name="password">MySQL password</param>
    /// <remarks>
    /// The MySQL server must be on localhost.
    /// If the server is on another host, a vulnerability
    /// is introduced wherein a remote device may inject
    /// false configuration information.
    /// </remarks>
    MySQLConfiguration(uint16_t port, const char *username, const char *password);
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~MySQLConfiguration();
    
    bool LocalIsOutdated();
    void UpdateLocal();
    bool GetDeviceKey(const struct ether_addr &mac_addr, DeviceKey_t &key);
    bool IsPermitted(const in_addr_t &src, const in_addr_t &dest);
    
private:
    uint16_t _port;
    std::string _username;
    std::string _password;
};

#endif