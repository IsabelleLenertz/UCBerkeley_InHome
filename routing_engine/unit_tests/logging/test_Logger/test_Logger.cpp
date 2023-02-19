#include "gtest/gtest.h"
#include "logging/Logger.hpp"

TEST(test_Logger, test_LogStdOut)
{
    Logger::SetLogStdOut(true);
    
    Logger::Log(LOG_FATAL, "This is a fatal error message");
    Logger::Log(LOG_ERROR, "This is an error message");
    Logger::Log(LOG_WARNING, "This is a warning message");
    Logger::Log(LOG_INFO, "This is an info message");
    Logger::Log(LOG_DEBUG, "This is a debug message");
}

TEST(test_Logger, test_LogFile)
{
    Logger::SetLogStdOut(false);
    Logger::OpenLogFile("test.txt");
    
    Logger::Log(LOG_FATAL, "This is a fatal error message");
    Logger::Log(LOG_ERROR, "This is an error message");
    Logger::Log(LOG_WARNING, "This is a warning message");
    Logger::Log(LOG_INFO, "This is an info message");
    Logger::Log(LOG_DEBUG, "This is a debug message");
    
    Logger::CloseLogFile();
}
