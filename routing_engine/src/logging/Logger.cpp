#include "logging/Logger.hpp"
#include <iomanip>
#include <arpa/inet.h>

std::mutex Logger::_mutex;
std::ofstream Logger::_file;
int Logger::_log_level = LOG_WARNING;
bool Logger::_log_stdout = false;

void Logger::SetLogLevel(int level)
{
    std::scoped_lock {_mutex};
    
    _log_level = level;
}

void Logger::SetLogStdOut(bool flag)
{
    std::scoped_lock {_mutex};
    
    _log_stdout = flag;
}

void Logger::OpenLogFile(const char *filepath)
{
    std::scoped_lock {_mutex};
    
    if (_file.is_open())
    {
        _file.close();
    }
    
    _file.open(filepath, std::ios::out);
}

void Logger::CloseLogFile()
{
    std::scoped_lock {_mutex};
    
    if (_file.is_open())
    {
        _file.close();
    }
}

void Logger::Log(int level, const char *message)
{
    std::scoped_lock {_mutex};
    
    if (level <= _log_level)
    {
        time_t _time = time(NULL);
        std::tm* _local = localtime(&_time);
    
        if (_log_stdout)
        {
            std::cout << std::put_time(_local, "%c");
            std::cout << " [" << level_strings[level] << "] ";
            std::cout << message << std::endl;
        }
        
        if (_file.is_open())
        {
            _file << std::put_time(_local, "%c");
            _file << " [" << level_strings[level] << "] ";
            _file << message << std::endl;
        }
    }
}

void Logger::Log(int level, const std::string &message)
{
    std::scoped_lock {_mutex};
    
    if (level <= _log_level)
    {
        time_t _time = time(NULL);
        std::tm* _local = localtime(&_time);
    
        if (_log_stdout)
        {
            std::cout << std::put_time(_local, "%c");
            std::cout << " [" << level_strings[level] << "] ";
            std::cout << message << std::endl;
        }
        
        if (_file.is_open())
        {
            _file << std::put_time(_local, "%c");
            _file << " [" << level_strings[level] << "] ";
            _file << message << std::endl;
        }
    }
}

std::string Logger::IPToString(const struct sockaddr &addr)
{
    switch (addr.sa_family)
    {
        case AF_INET:
        {
            const struct sockaddr_in &_addr = reinterpret_cast<const sockaddr_in&>(addr);
            char addr_str[16];
            
            inet_ntop(AF_INET, &_addr.sin_addr, addr_str, 16);
            return std::string(addr_str);
        }
        case AF_INET6:
        {
            const struct sockaddr_in6 &_addr = reinterpret_cast<const sockaddr_in6&>(addr);
            char addr_str[64];
            
            inet_ntop(AF_INET6, &_addr.sin6_addr, addr_str, 64);
            return std::string(addr_str);
        }
    }

    return "";
}
