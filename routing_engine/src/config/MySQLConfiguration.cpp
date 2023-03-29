#include "config/MySQLConfiguration.hpp"

const std::string MySQLConfiguration::HOST = "localhost";
const std::string MySQLConfiguration::USER = "root";
const std::string MySQLConfiguration::PASSWORD = "password";
const std::string MySQLConfiguration::DATABASE = "InHome";
const std::string MySQLConfiguration::REVISION_ID = "revisionId";
const std::string MySQLConfiguration::REVISION_DATE = "revisionDate DESC";
const std::string MySQLConfiguration::REVISION_TABLE = "revision";
const std::string MySQLConfiguration::POLICY_TABLE = "policies";
const std::string MySQLConfiguration::DEVICE_TABLE = "devices";

MySQLConfiguration::MySQLConfiguration(uint16_t port)
    : _port(port)
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

void MySQLConfiguration::UpdateLocal()
{
    // update cached set of policies
    mysql::RowResult result = mySession.getSchema(DATABASE).getTable(DEVICE_TABLE)
            .select(ALL)
            .execute();
      for(auto& row : rows) {
        sockaddr_in sock;  
        sock.sin_family = AF_INET;
        sock.sin_port = htons(0);

        // Ensure format of the table data.
        if (row.getBytes(IPV4).size() < sizeof(sock.sin_addr.s_addr)) continue;
        memcpy(&sock.sin_addr.s_addr, row.getBytes(IPV4).begin(), sizeof(sock.sin_addr.s_addr));

        ether_addr eth;
        if (row.getBytes(MAC).size() < sizeof(eth.ether_addr_octet)) continue;
        memcpy(eth.ether_addr_octet, row.getBytes(MAC).begin(), sizeof(eth.ether_addr_octet));
        
        devices->insert({eth, sock});
    }

    // update revision ID
    revisionId = LatestRevision();
    // TODO Implement
}

bool MySQLConfiguration::GetDeviceSecurityParams(const struct sockaddr &ip_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::GetDeviceSecurityParams(const struct ether_addr &mac_addr, DeviceSecParams_t &params)
{
    // TODO Implement
    return false;
}

bool MySQLConfiguration::IsPermitted(const struct sockaddr &src, const struct sockaddr &dest)
{
    return policies->find(Policy(*reinterpret_cast<const sockaddr_in*>(&src), *reinterpret_cast<const sockaddr_in*>(&dest))) != policies.end();
}
