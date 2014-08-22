/*
    File        : async_cmd.cpp
    Description : Implements every commands.
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

gerror_t async_cmd_unknown(std::vector<std::string> args, server_t*)
{
	cout << "[Command] Unknown command '" << args[0] << "' !" << endl;
	return GERROR_NONE;
}

/** @brief Log a user from the currently loaded database.
 *  
 *  @note 
 *  Command : userlogin [username] [password]
**/
gerror_t async_cmd_userlogin(std::vector<std::string> args, server_t* server)
{
	if(args.size() > 2)
	{
		std::string username = args[1];
		std::string pass     = args[2];
		int err = user_create(server->logged_user, username, pass);
		if(err == GERROR_NONE) {
			server->logged = true;
			cout << "[Command] Logged as '" << username << "'." << endl;
		}
		else
		{
			cout << "[Command] Error logging you in (" << gerror_to_string(err) << ")." << endl;
		}
	}
	
	return GERROR_NONE;
}

/** @brief Unlog the logged user. 
 *
 *  If user is not saved already in the database, it will.
 *  @note
 *  Command : userunlog
**/
gerror_t async_cmd_userunlog(std::vector<std::string>, server_t* server)
{
	user_destroy(server->logged_user);
	server->logged = false;
	cout << "[Command] Logged as 'null'." << endl;
	
	return GERROR_NONE;
}

/** @brief Open a connection with a client that should accept or deny you.
 *
 *  If you are already accepted in his database, then you should be directly 
 *  accepted. If you are new, it will send a request to the client to accept 
 *  you.
 *
 *  @note
 *  Command : userinit [ip] [port]
**/ 
gerror_t async_cmd_userinit(std::vector<std::string> args, server_t* server)
{
	// userinit -- Open a connection with a client that should accept 
	// or deny you. 
	// If you are already accepted in his database, then you should be directly
	// accepted. If you are new, it will send a request to the client to accept 
	// you.
			
	if(!server->logged)
	{
		cout << "[Command] You must be logged in to init your user connection !" << endl;
	}
			
	else
	{
		std::string ipclient   = args[1];
		std::string portclient = args[2];
		cout << "[Command] Initializing connection with identity '" << server->logged_user.name << "' to client '" << ipclient
			 << ":" << portclient << "'." << endl;
				
		user_t clientuser;
		if(server_init_user_connection(server, clientuser, ipclient.c_str(), atoi(portclient.c_str())) == GERROR_NONE)
		{
			cout << "[Command] User connected to '" << clientuser.name << "'." << endl;
		}
		else
		{
			cout << "[Command] Something bad happened. See log for more details." << endl;
		}
	}
	
	return GERROR_NONE;
}

/** @brief Display information about given connection.
 *
 *  @note
 *  Command : info [server|client] [client name]
**/
gerror_t async_cmd_info(std::vector<std::string> args, server_t* server)
{
	if(args.size() > 1)
	{
		if(args[1] == "server")
		{
			cout << "[Command] Server currently running at port : " << server->port << "."      << endl;
			cout << "[Command] Number of connected clients : " << server->clients.size() << "." << endl;
			return GERROR_NONE;
		}
		
		else if(args[1] == "client" && args.size() > 2)
		{
			client_t* info = server_find_client_by_name(server, args[2]);
			if(info)
			{
				cout << "[Command] Client " << info->name << " currently connected."                                                     << endl;
				cout << "[Command] Client adress : " << inet_ntoa(info->address.sin_addr) << ":" << ntohs(info->address.sin_port) << "." << endl;
				if(info->mirror != NULL)
				cout << "[Command] Client mirror : " << inet_ntoa(info->mirror->address.sin_addr) << ":" << ntohs(info->mirror->address.sin_port) << "." << endl;

				return GERROR_NONE;
			}
		}
	}

	else
	{
		cout << "[Command]<help> info [type] [client name]"                                      << endl;
		cout << "[Command]<help> Display information about given connection."                    << endl;
		cout << "[Command]<help> Type might be :"                                                << endl;
		cout << "[Command]<help>   - 'server' : displays information about this server."         << endl;
		cout << "[Command]<help>   - 'client' : displays information about given active client." << endl;
	}
	
	return GERROR_NONE;
}

/** @brief Open a new connection to given adress and port.
 *
 *  @note
 *  Command : openclient [ip] [port]
**/
gerror_t async_cmd_openclient(std::vector<std::string> args, server_t* server)
{
	if(args.size() > 2)
	{
		std::string adress = args[1];
		int         port   = atoi(args[2].c_str());

		client_t* new_client = nullptr;
		server_init_client_connection(server, new_client, adress.c_str(), port);
		if(!new_client)
			cout << "[Command] Can't initialize new client connection (adress='" << adress << "', port=" << port << ")." << endl;
	}

	else
	{
		cout << "[Command]<help> openclient [IP adress] [port]" << endl;
		cout << "[Command]<help> Open a new connection to given adress and port." << endl;
	}
	
	return GERROR_NONE;
}

/** @brief Close given client connection.
 *  @note
 *  Command : closeclient [client name]
**/
gerror_t async_cmd_closeclient(std::vector<std::string> args, server_t* server)
{
	if(args.size() > 1)
	{
		std::string name = args[1];
		server_end_client(server, name);
	}
	
	return GERROR_NONE;
}

/** @brief Send given file to given client.
 *  @note
 *  Command : sendfile [client name] [file path]
**/
gerror_t async_cmd_sendfile(std::vector<std::string> args, server_t* server)
{
	if(args.size() > 2)
	{
		client_t* to = server_find_client_by_name(server, args[1]);
		if(to != NULL && to->mirror != NULL)
		{
			client_send_file(to->mirror, args[2].c_str());
		}
	}

	else
	{
		cout << "[Command]<help> sendfile [client name] [file path]" << endl;
		cout << "[Command]<help> Send given file to given client."   << endl;
	}
	
	return GERROR_NONE;
}

GEND_DECL
