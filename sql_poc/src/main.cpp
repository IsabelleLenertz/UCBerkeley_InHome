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

using namespace std;

struct Device
{
  /* data */
  string name;
  uint64_t mac;
  uint64_t dateAdded;
  uint32_t ipv4;
};

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

int main(int argc, const char **argv)
{
  string url(argc >= 2 ? argv[1] : EXAMPLE_HOST);
  const string user(argc >= 3 ? argv[2] : EXAMPLE_USER);
  const string pass(argc >= 4 ? argv[3] : EXAMPLE_PASS);
  const string database(argc >= 5 ? argv[4] : EXAMPLE_DB);

  cout << "Connector/C++ tutorial framework..." << endl;
  cout << endl;
  mysqlx::Session mySession(mysqlx::SessionOption::HOST, "localhost",
                mysqlx::SessionOption::PORT, 33060,
                mysqlx::SessionOption::USER, user,
                mysqlx::SessionOption::PWD, pass);
  cout << "connected" << endl;
  // Use an SQL query to get the result
  mysqlx::Schema myDb = mySession.getSchema("InHome");
  cout << "got db" << endl;
  mysqlx::Table myTable = myDb.getTable("devices");
  mysqlx::RowResult res = myTable.select("*").execute();
  list<mysqlx::Row> rows = res.fetchAll();
  for(auto& row : rows) {
    cout << row.get(NAME) << endl;
    sockaddr_in sock;  
    sock.sin_family = AF_INET;
    sock.sin_port = htons(0);

    // Ensure format of the table data.
    if (row.getBytes(IPv4).size() < sizeof(sock.sin_addr.s_addr)) continue;
    memcpy(&sock.sin_addr.s_addr, row.getBytes(3).begin(), sizeof(sock.sin_addr.s_addr));

    ether_addr eth;
    if (row.getBytes(MAC).size() < sizeof(eth.ether_addr_octet)) continue;
    memcpy(eth.ether_addr_octet, row.getBytes(1).begin(), sizeof(eth.ether_addr_octet));

    std::cout << Logger::IPToString(reinterpret_cast<sockaddr&>(sock)) << std::endl;
  }
  cout << "Done." << endl;

  // Query the latest revision id
  res = myDb.getTable("revisions").select("revisionId").orderBy("revisionDate DESC").limit(1).execute();
  mysqlx::Row row = res.fetchOne(); 
  cout << endl << endl << row.get(0) << endl;
  return EXIT_SUCCESS;
}