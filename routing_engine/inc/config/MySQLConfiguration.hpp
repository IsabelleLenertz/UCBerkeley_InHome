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
    /// <remarks>
    /// The MySQL server must be on localhost.
    /// If the server is on another host, a vulnerability
    /// is introduced wherein a remote device may inject
    /// false configuration information.
    /// 
    /// Storing credentials in process memory is not ideal
    /// It is probably better to retrieve credentials when
    /// connecting to the server
    /// </remarks>
    MySQLConfiguration(uint16_t port);
    
    /// <summary>
    /// Destructor
    /// </summary>
    ~MySQLConfiguration();
    
    bool LocalIsOutdated();
    void UpdateLocal();
    
    bool IsPermitted(const struct sockaddr &src, const struct sockaddr &dest);
    
private:
    uint16_t _port;
    //std::string _username; // Do not store credentials
    //std::string _password;
};

#endif
