#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
/* uncomment for applications that use vectors */
/*#include <vector>*/

// Download the version that matches your ubuntu from here: https://dev.mysql.com/downloads/connector/cpp/8.0.html
//  sudo apt-get install /mnt/c/Users/Isabelle/Downloads/libmysqlcppconn-dev_8.0.32-1ubuntu22.04_amd64.deb
#include <mysqlx/xdevapi.h>

#define EXAMPLE_HOST "localhost"
#define EXAMPLE_USER "root"
#define EXAMPLE_PASS "password" //my-secret-pw or password
#define EXAMPLE_DB "InHome"

using namespace std;

struct Device
{
  /* data */
  string name;
  uint64_t mac;
  uint64_t dateAdded;
  uint32_t ipv4;
};


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
  for(mysqlx::Row row : rows) {
    cout <<  row.getBytes(0);
  }
  cout << "Done." << endl;
  return EXIT_SUCCESS;
}