#include "config/MySQLConfiguration.hpp"

#include <cstring>
#include <chrono>

const std::string MySQLConfiguration::HOST = "localhost";
const std::string MySQLConfiguration::USER = "root";
const std::string MySQLConfiguration::PASSWORD = "password";
const std::string MySQLConfiguration::DATABASE = "InHome";
const std::string MySQLConfiguration::REVISION_ID = "revisionId";
const std::string MySQLConfiguration::REVISION_DATE = "revisionDate DESC";
const std::string MySQLConfiguration::REVISION_TABLE = "revision";
const std::string MySQLConfiguration::POLICY_TABLE = "policies";
const std::string MySQLConfiguration::DEVICE_TABLE = "devices";
const std::string MySQLConfiguration::ALL = "*";

MySQLConfiguration::MySQLConfiguration(uint16_t port)
    : _port(port), mySession(mysqlx::SessionOption::HOST, HOST,
                             mysqlx::SessionOption::PORT, 33060,
                             mysqlx::SessionOption::USER, USER,
                             mysqlx::SessionOption::PWD, PASSWORD),
     updateThread(&MySQLConfiguration::UpdateThread, this)
{
    UpdateLocal();
}

MySQLConfiguration::~MySQLConfiguration()
{
    mySession.close();
}

bool MySQLConfiguration::LocalIsOutdated()
{
    return LatestRevision() > revisionId;
}

int MySQLConfiguration::LatestRevision()
{
    // Check if policy id of db is more recent that cached policy id
    mysqlx::RowResult result = mySession.getSchema(DATABASE).getTable(REVISION_TABLE)
            .select(REVISION_ID)
            .orderBy(REVISION_DATE)
            .limit(1)
            .execute();
    mysqlx::Row row = result.fetchOne(); 
    return row.get(REVISION_ID_COL);
}

void MySQLConfiguration::UpdateThread(void)
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (LocalIsOutdated()) {
            UpdateLocal();

                    /// PRINT TO DEBUG?

        }
    }
}

void MySQLConfiguration::UpdateLocal()
{
    // update cached set of policies
    revisionId = LatestRevision();
    mysqlx::RowResult result = mySession.getSchema(DATABASE).getTable(DEVICE_TABLE)
            .select(ALL)
            .execute();
    
    std::unique_ptr<std::unordered_map<ether_addr, sockaddr_in>> readDevices;
    for(const auto& row : result) {
        sockaddr_in sock;  
        sock.sin_family = AF_INET;
        sock.sin_port = htons(0);

        // Ensure format of the table data.
        if (row.getBytes(IPV4).size() < sizeof(sock.sin_addr.s_addr)) continue;
        memcpy(&sock.sin_addr.s_addr, row.getBytes(IPV4).begin(), sizeof(sock.sin_addr.s_addr));

        ether_addr eth;
        if (row.getBytes(MAC).size() < sizeof(eth.ether_addr_octet)) continue;
        memcpy(eth.ether_addr_octet, row.getBytes(MAC).begin(), sizeof(eth.ether_addr_octet));
        
        readDevices->insert({eth, sock});
    }

    std::lock_guard<std::mutex> lock(this->configMutex);            
    this->devices.swap(readDevices);
}

bool MySQLConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    std::lock_guard<std::mutex> lock(this->configMutex);            
    return policies->find(Policy(*reinterpret_cast<const sockaddr_in*>(&src), *reinterpret_cast<const sockaddr_in*>(&dest))) != policies->end();
}
