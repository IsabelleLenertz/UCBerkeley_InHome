#ifndef INC_MYSQLCONFIGURATION_HPP_
#define INC_MYSQLCONFIGURATION_HPP_

#include "config/IConfiguration.hpp"
#include <netinet/in.h>
#include <utility>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <iostream>
#include <cstring>
#include <mutex>
#include <mysqlx/xdevapi.h>
#include <thread>

// Download the version that matches your ubuntu from here: https://dev.mysql.com/downloads/connector/cpp/8.0.html
//  sudo apt-get install /mnt/c/Users/Isabelle/Downloads/libmysqlcppconn-dev_8.0.32-1ubuntu22.04_amd64.deb

namespace std {
    template <class T1, class T2>
    struct hash<pair<T1, T2>>
    {
        std::size_t operator()(const pair<T1, T2>& pair) const
        {
            auto hash1 = hash<T1>{}(pair.first);
            auto hash2 = hash<T2>{}(pair.second);
    
            if (hash1 != hash2) {
                return hash1 ^ hash2;             
            }
            return hash1;
        }
    };

    template <>
    struct hash<ether_addr>
    {
        std::size_t operator()(const ether_addr& node) const
        {
            return std::hash<std::string>{}(std::string(reinterpret_cast<const char*>(&node), sizeof(node)));
        }
    };

    template <>
    struct hash<sockaddr_in>
    {
        std::size_t operator()(const sockaddr_in& node) const
        {
            return std::hash<std::string>{}(std::string(reinterpret_cast<const char*>(&node), sizeof(node)));
        }
    };
};

static bool operator==(const ether_addr& lhs, const ether_addr& rhs)
{
    return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

static bool operator==(const sockaddr_in& lhs, const sockaddr_in& rhs)
{
    return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

/// <summary>
/// Concrete implementation of configuration module
/// using a MySQL server
/// </summary>
class MySQLConfiguration : public IConfiguration
{
private:

    std::thread updateThread;

    #define DEVICE1 1
    #define DEVICE2 2

    static const std::string HOST;
    static const std::string USER;
    static const std::string PASSWORD;
    static const std::string DATABASE;
    enum{
        MAC = 1,
        IPV4 = 3
    } deviceRow;
    static constexpr int REVISION_ID_COL = 0;
    static const std::string REVISION_ID;
    static const std::string REVISION_DATE;
    static const std::string REVISION_TABLE;
    static const std::string DEVICE_TABLE;
    static const std::string POLICY_TABLE;
    static const std::string ALL;


    mysqlx::Session mySession;

    typedef std::pair<sockaddr_in, sockaddr_in> Policy;
    uint16_t _port;
    int revisionId;

    std::unique_ptr<std::unordered_map<ether_addr, sockaddr_in>> devices;
    std::unique_ptr<std::unordered_set<Policy>> policies;
    std::mutex configMutex;

    //std::string _username; // Do not store credentials
    //std::string _password;
    int LatestRevision();
    void UpdateThread(void);

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
};

#endif
