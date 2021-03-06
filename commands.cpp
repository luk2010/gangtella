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

std::streambuf* coutbuf              = nullptr;
std::string     console_last_command = "";

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

/** @brief Wait for a command to be typed.
 *  
 *  If you want the user to type something for you that is not a valid command, use 
 *  this method to retrieve it. 
 *
 *  Use : 
 *  console_reset_lastcommand(); 
 *  console_waitfor_command();
 *  std::string customcmd = console_get_lastcommand();
 *
 *  @note
 *  This function is blocking. It is not very thread-safe, you should use it with care.
**/
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
    bool                     inbackground;
} async_cmd_private_t;

void* async_cmd_thread_loop (void* d)
{
    globalsession._treatingcommand = true;
    
	async_cmd_private_t* data = (async_cmd_private_t*) d;
    
    if(data->inbackground) globalsession._treatingcommand = false;
	
    if(data)
    {
		data->cmd(data->args, data->server);
        delete data;
    }
	
    globalsession._treatingcommand = false;
	return NULL;
}

/** @brief Launch a thread to process given command.
 *
 *  @param cmd_type : The command to execute.
 *  @param args     : A vector containing every args in the command line. @note args[0] is the
 *  command name.
 *  @param server   : A pointer to the current server.
 *  @param _background : Set this to true if you want the command to be launched in background.
 *
**/
void async_command_launch(int cmd_type, const std::vector<std::string>& args, server_t* server, bool _background)
{
	if(cmd_type < CMD_MAX && cmd_type > CMD_UNKNOWN)
	{
		command_func_t cmd = async_commands[cmd_type].callback;
		
		async_cmd_private_t* cmd_private = new async_cmd_private_t;
		cmd_private->cmd    = cmd;
		cmd_private->args   = args;
		cmd_private->server = server;
        cmd_private->inbackground = _background;
		
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
	{ CMD_SENDFILE,    async_cmd_sendfile    },
	{ CMD_USERCHECK,   async_cmd_usercheck   },
    { CMD_NET_ATTACH,  async_cmd_netattach   },
    
    // New API
    
    { CMD_VERSION,     async_cmd_version     }
};

GEND_DECL
