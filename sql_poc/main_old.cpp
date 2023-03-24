#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
/* uncomment for applications that use vectors */
/*#include <vector>*/

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>

#define EXAMPLE_HOST "localhost"
#define EXAMPLE_USER "root"
#define EXAMPLE_PASS "password"
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

  try {
    sql::Driver* driver = get_driver_instance();
    std::unique_ptr<sql::Connection> con(driver->connect(url, user, pass));
    con->setSchema(database);
    std::unique_ptr<sql::Statement> stmt(con->createStatement());

    auto res = stmt->executeQuery("SELECT * FROM devices");
    while (res->next()) {
      // The latter is recommended.
      Device mydevice = {};
      mydevice.dateAdded = res->getUInt64("dateAdded");
      mydevice.mac = res->getUInt64("Mac"); // problem, this is actualy a 64 bit array, not an integer
      mydevice.name = res->getString("Name");
      mydevice.ipv4 = res->getUInt("Ipv4"); // prolem, this is actualy a 32 bit array, not an integer

      cout << mydevice.name << endl;
      cout << "date added: " << mydevice.dateAdded << endl;
      cout << "MAC: " << mydevice.mac << endl;
      cout << "Ipv4: " << mydevice.ipv4 << endl << endl;
    }

  } catch (sql::SQLException &e) {
    /*
      MySQL Connector/C++ throws three different exceptions:
      - sql::MethodNotImplementedException (derived from sql::SQLException)
      - sql::InvalidArgumentException (derived from sql::SQLException)
      - sql::SQLException (derived from std::runtime_error)
    */
    cout << "# ERR: SQLException in " << __FILE__;
    cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;
    /* what() (derived from std::runtime_error) fetches error message */
    cout << "# ERR: " << e.what();
    cout << " (MySQL error code: " << e.getErrorCode();
    cout << ", SQLState: " << e.getSQLState() << " )" << endl;

    return EXIT_FAILURE;
  }

  cout << "Done." << endl;
  return EXIT_SUCCESS;
}