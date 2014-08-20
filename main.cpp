/*
    File        : main.cpp
    Description : Creates the server and treats commands.
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

#include "prerequesites.h"
#include "commands.h"
#include "packet.h"
#include "client.h"
#include "server.h"

using namespace Gangtella;

server_t  server;

void treat_command(const std::string& command)
{
    std::vector<std::string> args;

    char c_command[command.size() + 1];
    memcpy(c_command, command.c_str(), command.size());
    c_command[command.size()] = '\0';
    char* tok = strtok(c_command, " ");
    while(tok != NULL)
    {
        args.push_back(tok);
        tok = strtok(NULL, " ");
    }

    if(!args.empty())
    {
        if(args[0] == "message")
        {
            if(args.size() > 2)
            {
                client_t* to = server_find_client_by_name(&server, args[1]);
                if(to != NULL && to->mirror != NULL)
                {
                    char buffer[SERVER_MAXBUFSIZE];
                    memset(buffer, 0, SERVER_MAXBUFSIZE);
                    memcpy(buffer, command.c_str() + 8 + args[1].size() + 1, command.size() - 8 - args[1].size() - 1);
                    client_send_cryptpacket(to->mirror, PT_CLIENT_MESSAGE, buffer, SERVER_MAXBUFSIZE);
                }
            }

            else
            {
                cout << "[Command]<help> message [client name] [message]"        << endl;
                cout << "[Command]<help> Send a message to given active client." << endl;
            }
        }



        else if(args[0] == "messageall")
        {
            if(args.size() > 1)
            {
                for(unsigned int i = 0; i < server.clients.size(); ++i)
                {
                    client_t* to = &(server.clients[i]);
                    if(to != NULL && to->mirror != NULL)
                    {
                        client_send_packet(to->mirror, PT_CLIENT_MESSAGE, command.c_str() + 11, command.size() - 11);
                    }
                }
            }

            else
            {
                cout << "[Command]<help> messageall [message]"                    << endl;
                cout << "[Command]<help> Send a message to every active clients." << endl;
            }
        }



        else if(args[0] == "info")
        {
            if(args.size() > 1)
            {
                if(args[1] == "server")
                {
                    cout << "[Command] Server currently running at port : " << server.port << "."      << endl;
                    cout << "[Command] Number of connected clients : " << server.clients.size() << "." << endl;
                    return;
                }
                else if(args[1] == "client" && args.size() > 2)
                {
                    client_t* info = server_find_client_by_name(&server, args[2]);
                    if(info)
                    {
                        cout << "[Command] Client " << info->name << " currently connected."                                                     << endl;
                        cout << "[Command] Client adress : " << inet_ntoa(info->address.sin_addr) << ":" << ntohs(info->address.sin_port) << "." << endl;
                        if(info->mirror != NULL)
                        cout << "[Command] Client mirror : " << inet_ntoa(info->mirror->address.sin_addr) << ":" << ntohs(info->mirror->address.sin_port) << "." << endl;

                        return;
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
        }


        else if(args[0] == "sendfile")
        {
            if(args.size() > 2)
            {
                client_t* to = server_find_client_by_name(&server, args[1]);
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
        }


        else if(args[0] == "openclient")
        {
            if(args.size() > 2)
            {
                std::string adress = args[1];
                int         port   = atoi(args[2].c_str());

                client_t* new_client = nullptr;
                server_init_client_connection(&server, new_client, adress.c_str(), port);
                if(!new_client)
                    cout << "[Command] Can't initialize new client connection (adress='" << adress << "', port=" << port << ")." << endl;
            }

            else
            {
                cout << "[Command]<help> openclient [IP adress] [port]" << endl;
                cout << "[Command]<help> Open a new connection to given adress and port." << endl;
            }
        }

        else if(args[0] == "closeclient")
        {
            if(args.size() > 1)
            {
                std::string name = args[1];
                server_end_client(&server, name);
            }
        }
        
        else if(args[0] == "userlogin")
		{
			if(args.size() > 2)
			{
				std::string username = args[1];
				std::string pass     = args[2];
				int err = user_create(server.logged_user, username, pass);
				if(err == GERROR_NONE) {
					server.logged = true;
					cout << "[Command] Logged as '" << username << "'." << endl;
				}
				else
				{
					cout << "[Command] Error logging you in (" << gerror_to_string(err) << ")." << endl;
				}
			}
		}
		
		else if(args[0] == "userunlog")
		{
			user_destroy(server.logged_user);
			server.logged = false;
			cout << "[Command] Logged as 'null'." << endl;
		}
		
		else if(args[0] == "userinit")
		{
			// userinit -- Open a connection with a client that should accept 
			// or deny you. 
			// If you are already accepted in his database, then you should be directly
			// accepted. If you are new, it will send a request to the client to accept 
			// you.
			
			if(!server.logged)
			{
				cout << "[Command] You must be logged in to init your user connection !" << endl;
			}
			
			else
			{
				std::string ipclient   = args[1];
				std::string portclient = args[2];
				cout << "[Command] Initializing connection with identity '" << server.logged_user.name << "' to client '" << ipclient
				     << ":" << portclient << "'." << endl;
				
				user_t clientuser;
				if(server_init_user_connection(&server, clientuser, ipclient.c_str(), atoi(portclient.c_str())) == GERROR_NONE)
				{
					cout << "[Command] User connected to '" << clientuser.name << "'." << endl;
				}
				else
				{
					cout << "[Command] Something bad happened. See log for more details." << endl;
				}
			}
		}
    }
    
    console_last_command = command;
}

void bytes_callback(const std::string& name, size_t current, size_t total)
{
    cout << "\r " << name << " : ";
    cout << current << " \\ " << total << "bytes";
    cout << " |";

    size_t chunk_total = 30;
    size_t sz_for_one  = total / chunk_total;
    size_t chunk_num   = current / sz_for_one;
    size_t blanck_num  = chunk_total - chunk_num;

    for(size_t i = 0; i < chunk_num; ++i)
        cout << "#";
    for(size_t i = 0; i < blanck_num; ++i)
        cout << " ";

    cout << "| ";
    size_t perc = (100 * chunk_num) / chunk_total;
    cout << perc << "%";
}

void display_help()
{
    cout << "GangTella is a free server&client connector to the Gang Network." << endl;
    cout << "This program is FREE SOFTWARE and is distributed with NO WARRANTY." << endl;
    cout << "If you have any kind of problems with it, " << endl;
	cout << "you can send a mail to 'alain.ratatouille@gmail.com' (for suggestions it is the same adress :) ) . " << endl; cout
	     << "Uses    : gangtella [options]" << endl; cout
		 << "Options : " << endl; cout
			<< " --s-port      : Specify a custom port for the Server."             << endl; cout
			<< "                 Default is 8377."                                  << endl; cout
			<< " --s-name      : Specify a custom name for the Server. This name "  << endl; cout
			<< "                 is shown to every one who connect to this server." << endl; cout
			<< " --c-adress    : Specify the IP adress for the automated"           << endl; cout
			<< "                 created client. Default is 127.0.0.1 (for test)."  << endl; cout
			<< " --c-port      : Specify a port for the automated created client."  << endl; cout
			<< "                 Default is 8378."                                  << endl; cout
			<< " --no-client   : Specify the program not to create a client at the" << endl; cout
			<< "                 beginning. This option is cool when you do not "   << endl; cout
			<< "                 test the program."                                 << endl; cout
			<< " --max-clients : Specify a max number of clients. Default is 10."   << endl; cout
			<< " --max-buffer  : Specify the Maximum buffer size for a packet. "    << endl; cout
			<< "                 Default is 1096."                                  << endl; cout
			<< " --help        : Show this text."                                   << endl; cout
			<< " --usr-help    : Show a help text on how to connect to the Network."<< endl; cout
			<< " --version     : Show the version number."                          << endl;
}

void display_user_help()
{
	cout << "GangTella is a free server&client connector to the Gang Network." << endl;
    cout << "This program is FREE SOFTWARE and is distributed with NO WARRANTY." << endl;
    cout << "If you have any kind of problems with it, " << endl;
	cout << "you can send a mail to 'alain.ratatouille@gmail.com' (for suggestions it is the same adress :) ) . " << endl; cout
		 << "User connection : You need a password and a username. Then, it will connect to the nearest " << endl; cout
		 << "trusted server wich will approve (if it knows you) or disapprove you to enter the network." << endl; 
}

int main(int argc, char* argv[])
{
    cout << "GangTella v." << GANGTELLA_VERSION << "."  << endl;

    // Init OpenSSL
    Encryption::Init();

    // Argues

    int server_port           = SERVER_PORT;
    std::string server_name   = "Default";
    std::string client_adress = "127.0.0.1";
    int client_port           = CLIENT_PORT;
    bool with_client          = false;
    int server_max_clients    = SERVER_MAXCLIENTS;
    int server_max_bufsize    = SERVER_MAXBUFSIZE;

    for(int i = 0; i < argc; ++i)
    {
        if(std::string("--s-port") == argv[i])
        {
            server_port = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--s-name") == argv[i])
        {
            server_name = argv[i+1];
            i++;
        }
        else if(std::string("--c-adress") == argv[i])
        {
            client_adress = argv[i+1];
            i++;
        }
        else if(std::string("--c-port") == argv[i])
        {
            client_port = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--no-client") == argv[i])
        {
            with_client = false;
        }
        else if(std::string("--max-clients") == argv[i])
        {
            server_max_clients = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--max-buffer") == argv[i])
        {
            server_max_bufsize = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--help") == argv[i])
        {
            display_help();
            return 0;
        }
        else if(std::string("--usr-help") == argv[i])
		{
			display_user_help();
			return 0;
		}
		else if(std::string("--version") == argv[i])
		{
			return 0;
		}
    }

#ifdef GULTRA_DEBUG
    cout << "[Main] Server Name   = '" << server_name << "'." << endl;
    cout << "[Main] Server Port   = '" << server_port << "'." << endl;
    if(with_client) {
    cout << "[Main] Client Adress = '" << client_adress << "'." << endl;
    cout << "[Main] Client Port   = '" << client_port << "." << endl;
    }

    cout << "[Main] Server Max Client = '" << server_max_clients << "'." << endl;
    cout << "[Main] Server Max Buffer = '" << server_max_bufsize << "'." << endl;

#endif // GULTRA_DEBUG

    server_create(&server, server_name);
    server_initialize(&server, server_port, server_max_clients);
    server_setsendpolicy(&server, Gangtella::SP_CRYPTED);
#ifndef GULTRA_DEBUG
    server_setbytesreceivedcallback(&server, bytes_callback);
    server_setbytessendcallback(&server, bytes_callback);
#endif // GULTRA_DEBUG

    // Creation thread serveur
    cout << "[Main] Creating Server thread." << endl;
    if(server_launch(&server) != GERROR_NONE)
    {
        std::cerr << "[Main] Couldn't launch server !!! Aborting." << endl;
        return 0;
    }

    // Waiting for server to be done
    while(server.started == false)
        usleep(2000);

    // Creation du client de test
    if(with_client)
    {
        cout << "[Main] Initializing client." << endl;
        client_t* tmp = nullptr; server_init_client_connection(&server, tmp, client_adress.c_str(), client_port);
    }

    // Waiting for client to be done
    usleep(2000);

    std::string tmp;
    while(1)
    {
        char buf[server_max_bufsize];
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);
        std::cin.getline(buf, server_max_bufsize - 1);
        tmp = buf;
        if(tmp == "exit")
        {
            cout << "[Main] Exiting." << endl;
            pthread_cancel(server.thread);
            server_destroy(&server);
            break;
        }
        else
        {
            treat_command(tmp);
        }
    }

    cout << "[Main] Goodbye." << endl;
    return 0;
}
