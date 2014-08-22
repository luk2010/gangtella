/*
    File        : commands.cpp
    Description : Implements every console related functions.
*/

/*
    GangTella Project
    Copyright (C) 2014  Luk2010

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "commands.h"

GBEGIN_DECL

std::streambuf* coutbuf = nullptr;
std::string console_last_command = "";

#undef cout
#undef endl

gerror_t console_set_output(std::ostream& os)
{
    coutbuf = cout.rdbuf();
    cout.rdbuf(os.rdbuf());

    return GERROR_NONE;
}

gerror_t console_restore_output()
{
    if(coutbuf)
        cout.rdbuf(coutbuf);

    coutbuf = nullptr;
    return GERROR_NONE;
}

void console_reset_lastcommand()
{
	console_last_command.clear();
}

std::string console_get_lastcommand()
{
	return console_last_command;
}

void console_waitfor_command()
{
	std::string cpy = console_last_command;
	while(console_last_command == cpy);
}

typedef struct 
{
	command_func_t           cmd;
	std::vector<std::string> args;
	server_t*                server;
} async_cmd_private_t;

void* async_cmd_thread_loop (void* d)
{
	async_cmd_private_t* data = (async_cmd_private_t*) d;
	
	if(data)
		data->cmd(data->args, data->server);
	
	return NULL;
}

/** @brief Launch a thread to process given command.
 *
 *  @param cmd_type : The command to execute.
 *  @param args     : A vector containing every args in the command line. @note args[0] is the
 *  command name.
 *  @param server   : A pointer to the current server.
 *
**/
void async_command_launch(int cmd_type, const std::vector<std::string>& args, server_t* server)
{
	if(cmd_type < CMD_MAX && cmd_type > CMD_UNKNOWN)
	{
		command_func_t cmd = async_commands[cmd_type].callback;
		
		async_cmd_private_t* cmd_private = new async_cmd_private_t;
		cmd_private->cmd    = cmd;
		cmd_private->args   = args;
		cmd_private->server = server;
		
		pthread_t _thread;
		pthread_create(&_thread, 0, async_cmd_thread_loop, cmd_private);
	}
}

async_cmd_t async_commands [CMD_MAX] = 
{
	{ CMD_UNKNOWN,     async_cmd_unknown     },
	{ CMD_USERLOGIN,   async_cmd_userlogin   },
	{ CMD_USERUNLOG,   async_cmd_userunlog   },
	{ CMD_USERINIT,    async_cmd_userinit    },
	{ CMD_INFO,        async_cmd_info        },
	{ CMD_OPENCLIENT,  async_cmd_openclient  },
	{ CMD_CLOSECLIENT, async_cmd_closeclient },
	{ CMD_SENDFILE,    async_cmd_sendfile    }
};

GEND_DECL
