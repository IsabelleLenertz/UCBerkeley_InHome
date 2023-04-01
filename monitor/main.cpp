#include "monitor/MonitorReceiver.hpp"

int main(int argc, char *argv[])
{
    MonitorReceiver monitor;
    
    monitor.Initialize(12001);
    
    while(1);

    return 0;
}
