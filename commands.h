/*
    File        : commands.h
    Description : Defines every console related functions.
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

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include "prerequesites.h"
#include "server.h"

GBEGIN_DECL

extern std::string console_last_command;

gerror_t console_set_output(std::ostream& os);
gerror_t console_restore_output();

void        console_reset_lastcommand();
std::string console_get_lastcommand();
void 		console_waitfor_command();

typedef gerror_t (*command_func_t) (std::vector<std::string> args, server_t* server);
typedef enum {
	CMD_UNKNOWN     = 0,
	CMD_USERLOGIN   = 1,
	CMD_USERUNLOG   = 2,
	CMD_USERINIT    = 3,
	CMD_INFO        = 4,
	CMD_OPENCLIENT  = 5,
	CMD_CLOSECLIENT = 6,
	CMD_SENDFILE    = 7,
	
	CMD_MAX         = 8
} Commands;

typedef struct async_cmd_
{
	int            cmd_id;   // This corresponds to the id of Commands enum.
	command_func_t callback; // This corresponds to the function callback used for this command.
} async_cmd_t;

void async_command_launch(int cmd_type, const std::vector<std::string>& args, server_t* server);

gerror_t async_cmd_unknown     (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_userlogin   (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_userunlog   (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_userinit    (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_info        (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_openclient  (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_closeclient (std::vector<std::string> args, server_t* server);
gerror_t async_cmd_sendfile    (std::vector<std::string> args, server_t* server);

// This array makes us call any commands where we want.
extern async_cmd_t async_commands[CMD_MAX];

GEND_DECL

#endif // __COMMANDS_H__
