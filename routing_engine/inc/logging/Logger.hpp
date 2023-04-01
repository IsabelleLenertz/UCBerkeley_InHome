#ifndef INC_LOGGER_HPP_
#define INC_LOGGER_HPP_

#include <string>
#include <sstream>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>

#define LOG_FATAL   0
#define LOG_SECURE  1
#define LOG_ERROR   2
#define LOG_WARNING 3
#define LOG_INFO    4
#define LOG_DEBUG   5
#define LOG_VERBOSE 6

class Logger
{
public:
    /// <summary>
    /// Sets the current log level.
    /// All messages equal of equal or lesser
    /// log level are logged.
    /// </summary>
    /// <param name="level">Log level</param>
    static void SetLogLevel(int level);
    
    /// <summary>
    /// Sets whether the logger should log
    /// to std::out
    /// </summary>
    /// <param name="flag">True to log to std::out</param>
    static void SetLogStdOut(bool flag);
    
    /// <summary>
    /// Opens the specified file for logging
    /// </summary>
    /// <param name="filepath">File to open</param>
    static void OpenLogFile(const char *filepath);
    
    /// <summary>
    /// Closes the currently open log file
    /// </summary>
    static void CloseLogFile();

    /// <summary>
    /// Logs the specified null-terminated message
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <param name="message">Message to log</param>
    static void Log(int level, const char *message);
    
    /// <summary>
    /// Logs the specified std::string message
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <param name="message">Message to log</param>
    static void Log(int level, const std::string &message);
    
    /// <summary>
    /// Logs the specified std::stringstream message
    /// </summary>
    /// <param name="level">Message log level</param>
    /// <param name="message">Message to log</param>
    static void Log(int level, const std::stringstream &message);
    
    /// <summary>
    /// Returns a std::string object containing the
    /// presentation format of the specified address
    /// </summary>
    /// <param name="addr">Address</param>
    /// <returns>String</returns>
    static std::string IPToString(const struct sockaddr &addr);

    /// <summary>
    /// Returns a std::string object containing the
    /// input byte array, represented as hex values
    /// </summary>
    /// <param name="data">Byte array</param>
    /// <param name="len">Length of data, in bytes</param>
    /// <returns>String</returns>
    static std::string BytesToString(const uint8_t *data, size_t len);

private:
    static std::mutex _mutex;
    static std::ofstream _file;
    static int _log_level;
    static bool _log_stdout;
    
    static constexpr char* level_strings[LOG_VERBOSE + 1] = {" FATAL ", "SECURE ", " ERROR ", " WARN  ", " INFO  ", " DEBUG ", "VERBOSE"};
};

#endif
