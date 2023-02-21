#include "layer3/Layer3Router.hpp"
#include "logging/Logger.hpp"
#include <iomanip>
#include <ctime>
#include <sstream>

#include <filesystem>

#define EXEC_NAME "route_test"

/// <summary>
/// Structure to store results when
/// parsing command-line arguments
/// </summary>
typedef struct
{
	int log_level;
	bool log_stdout;
	bool help_requested;
} CmdConfig_t;

int ParseShortFlags(const char *arg, CmdConfig_t &cmd_cfg);
int ParseLongFlag(const char *arg, CmdConfig_t &cmd_cfg);
int ParseCommandLine(int argc, char *argv[], CmdConfig_t &cmd_cfg);

int main(int argc, char *argv[])
{
	Logger::SetLogStdOut(true);
	Logger::SetLogLevel(LOG_VERBOSE);

	CmdConfig_t cmd_cfg
	{
		LOG_WARNING,
		true,
		false
	};

	int status = ParseCommandLine(argc, argv, cmd_cfg);

	if (status != 0 || cmd_cfg.help_requested)
	{
		std::cout << EXEC_NAME << " [-h | --help] [-s] [-v]" << std::endl;
		std::cout << "    " << "-h | --help : Display Help Text" << std::endl;
		std::cout << "    " << "-s : Enable print to standard out" << std::endl;
		std::cout << "    " << "-v : Enable verbose logging" << std::endl;
	}
	else
	{
		// Get time
		time_t _time = time(NULL);
		std::tm* _local = localtime(&_time);

		std::stringstream logfolder;
		logfolder << "/var/log/" << EXEC_NAME;
		std::filesystem::path path(logfolder.str().c_str());
		bool path_exists = std::filesystem::exists(path);
		if (!path_exists)
		{
			path_exists = std::filesystem::create_directory(path);
		}

		Logger::SetLogLevel(cmd_cfg.log_level);
		Logger::SetLogStdOut(cmd_cfg.log_stdout);

		if (path_exists)
		{
		    std::stringstream sstream;
		    sstream << logfolder.str() << "/log_" << std::put_time(_local, "%Y_%m_%d_%H_%M_%S") << ".txt";
		    Logger::OpenLogFile(sstream.str().c_str());
		}

		Logger::Log(LOG_INFO, "Starting Router");

		// Instantiate Router
		Layer3Router router;

		status = router.Initialize();

		if (status == 0)
		{
			router.MainLoop();
		}
		else
		{
			Logger::Log(LOG_FATAL, "Failed to Initialize Router");
		}

		Logger::Log(LOG_INFO, "Shutting Down");
		Logger::CloseLogFile();
	}

    return 0;
}

int ParseCommandLine(int argc, char *argv[], CmdConfig_t &cmd_cfg)
{
	int status = 0;

	for (int i = 1; i < argc; i++)
	{
		std::string token(argv[i]);

		if (token.size() == 0)
		{
			// Empty token
			continue;
		}
		else
		{
			if (token[0] == '-')
			{
				if (token.size() < 2)
				{
					// Blank flag
					continue;
				}
				else if (token[1] == '-')
				{
					// Long flag
					status |= ParseLongFlag(token.c_str() + 2, cmd_cfg);
				}
				else
				{
					// Short flag(s)
					status |= ParseShortFlags(token.c_str() + 1, cmd_cfg);
				}
			}
		}
	}

	return status;
}

int ParseShortFlags(const char *arg, CmdConfig_t &cmd_cfg)
{
	int status = 0;

	const char *c = arg;
	while (*c != '\0')
	{
		switch (*c)
		{
		    case 's':
		    {
		    	cmd_cfg.log_stdout = true;
		    	break;
		    }
		    case 'v':
		    {
		    	cmd_cfg.log_level = LOG_VERBOSE;
		    	break;
		    }
		    case 'h':
		    {
		    	cmd_cfg.help_requested = true;
		    	break;
		    }
		    default:
		    {
		    	status = 1;
		    	break;
		    }
		}

		c++;
	}

	return status;
}

int ParseLongFlag(const char *arg, CmdConfig_t &cmd_cfg)
{
	int status = 0;

    if (strcmp("help", arg) == 0)
    {
    	cmd_cfg.help_requested = true;
    }
    else
    {
    	status = 1;
    }

    return status;
}
