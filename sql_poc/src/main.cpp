#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <typeinfo>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../../routing_engine/inc/logging/Logger.hpp"
#include <net/ethernet.h>

/* uncomment for applications that use vectors */
/*#include <vector>*/

// Download the version that matches your ubuntu from here: https://dev.mysql.com/downloads/connector/cpp/8.0.html
//  sudo apt-get install /mnt/c/Users/Isabelle/Downloads/libmysqlcppconn-dev_8.0.32-1ubuntu22.04_amd64.deb
#include <mysqlx/xdevapi.h>

#define EXAMPLE_HOST "localhost"
#define EXAMPLE_USER "root"
#define EXAMPLE_PASS "password" //my-secret-pw or password
#define EXAMPLE_DB "InHome"
#define MAC 1
#define IPv4 3
#define NAME 0
#define REVISION_ID_COL 0
#define REVISION_ID "revisionId"
#define REVISION_DATE "revisionDate DESC"
#define DEVICE_TABLE "devices"
#define DEVICE1 1
#define DEVICE2 2
#define POLICIES_TABLE "policies"
#define REVISION_TABLE "revision"
#define ALL "*"

struct Device
{
  sockaddr_in ip;
  ether_addr mac;
};


typedef std::pair<sockaddr_in, sockaddr_in> Policy;
std::list<Policy> policyList;




using namespace std;

template <typename IntegerType>
IntegerType bitsToInt( IntegerType& result, const unsigned char* bits, bool little_endian = true )
{
result = 0;
if (little_endian)
  for (int n = sizeof( result ); n >= 0; n--)
    result = (result << 8) +bits[ n ];
else
  for (unsigned n = 0; n < sizeof( result ); n++)
    result = (result << 8) +bits[ n ];
return result;
}

bool compareBytes(byte* array1ptr, byte* array2ptr, int length)
{
  for(int i = 0; i < length; i++)
  {
    if(&array1ptr != &array2ptr) return false;
  }
  return true;
}

int main(int argc, const char **argv)
{
  string url(argc >= 2 ? argv[1] : EXAMPLE_HOST);
  const string user(argc >= 3 ? argv[2] : EXAMPLE_USER);
  const string pass(argc >= 4 ? argv[3] : EXAMPLE_PASS);
  const string database(argc >= 5 ? argv[4] : EXAMPLE_DB);

  cout << "Connector/C++ tutorial framework..." << endl;
  cout << endl;
  mysqlx::Session mySession(mysqlx::SessionOption::HOST, url,
                mysqlx::SessionOption::PORT, 33060,
                mysqlx::SessionOption::USER, user,
                mysqlx::SessionOption::PWD, pass);
  cout << "connected" << endl;
  // Use an SQL query to get the result
  mysqlx::Schema myDb = mySession.getSchema(database);
  cout << "got db" << endl;
  mysqlx::Table myTable = myDb.getTable(DEVICE_TABLE);
  mysqlx::RowResult res = myTable.select(ALL).execute();
  list<mysqlx::Row> rows = res.fetchAll();
  list<Device> devices;
  for(auto& row : rows) {
    cout << row.get(NAME) << endl;
    sockaddr_in sock;  
    sock.sin_family = AF_INET;
    sock.sin_port = htons(0);

    // Ensure format of the table data.
    if (row.getBytes(IPv4).size() < sizeof(sock.sin_addr.s_addr)) continue;
    memcpy(&sock.sin_addr.s_addr, row.getBytes(IPv4).begin(), sizeof(sock.sin_addr.s_addr));

    ether_addr eth;
    if (row.getBytes(MAC).size() < sizeof(eth.ether_addr_octet)) continue;
    memcpy(eth.ether_addr_octet, row.getBytes(MAC).begin(), sizeof(eth.ether_addr_octet));

    // Update list of devices
    Device currentDevice;
    currentDevice.ip = sock;
    currentDevice.mac = eth;
    devices.push_back(currentDevice);
    std::cout << Logger::IPToString(reinterpret_cast<sockaddr&>(sock)) << std::endl;
  }
  cout << "Done. number of devices: " << devices.size() << endl;

  // Query the latest revision id
  res = myDb.getTable(REVISION_TABLE).select(REVISION_ID).orderBy(REVISION_DATE).limit(1).execute();
  mysqlx::Row row = res.fetchOne(); 
  cout << endl << endl << row.get(REVISION_ID_COL) << endl;

  res = myDb.getTable(POLICIES_TABLE).select(ALL).execute();
  list<mysqlx::Row> policies = res.fetchAll();
  for (auto& policy : policies) {
    ether_addr eth;
    if (row.getBytes(DEVICE1).size() < sizeof(eth.ether_addr_octet)) continue;
    memcpy(eth.ether_addr_octet, row.getBytes(DEVICE1).begin(), sizeof(eth.ether_addr_octet));

  }

  // Check if 2 devices are allowed to communicate given 2 IP addresses
  // mysqlx::SqlResult sqlResult= mySession.sql("SELECT Ipv4 from InHome.devices JOIN InHome.policies ON devices.Mac = policies.deviceTo;").execute();
  // cout << sqlResult.fetchOne().getBytes(0).begin() << endl;

  return EXIT_SUCCESS;
}