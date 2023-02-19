#include "layer3/Layer3Router.hpp"
#include "logging/Logger.hpp"
#include <iomanip>
#include <ctime>
#include <sstream>

int main(int argc, char *argv[])
{
    // Get time
    time_t _time = time(NULL);
    std::tm* _local = localtime(&_time);
    
    std::stringstream sstream;
    sstream << "logs/log_" << std::put_time(_local, "%Y_%m_%d_%H_%M_%S") << ".txt";
    
    Logger::SetLogLevel(LOG_INFO);
    Logger::OpenLogFile(sstream.str().c_str());
    Logger::SetLogStdOut(true);
    
    Logger::Log(LOG_INFO, "Starting Router");

    // Instantiate Router
    Layer3Router router;
    
    router.Initialize();
    
    router.MainLoop();
    
    Logger::CloseLogFile();

    return 0;
}
