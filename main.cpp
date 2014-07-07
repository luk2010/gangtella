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
                std::cout << "[Command]<help> message [client name] [message]"        << std::endl;
                std::cout << "[Command]<help> Send a message to given active client." << std::endl;
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
                std::cout << "[Command]<help> messageall [message]"                    << std::endl;
                std::cout << "[Command]<help> Send a message to every active clients." << std::endl;
            }
        }



        else if(args[0] == "info")
        {
            if(args.size() > 1)
            {
                if(args[1] == "server")
                {
                    std::cout << "[Command] Server currently running at port : " << SERVER_PORT << "."      << std::endl
                              << "[Command] Number of connected clients : " << server.clients.size() << "." << std::endl;
                    return;
                }
                else if(args[1] == "client" && args.size() > 2)
                {
                    client_t* info = server_find_client_by_name(&server, args[2]);
                    if(info)
                    {
                        std::cout << "[Command] Client " << info->name << " currently connected."                                                                    << std::endl
                                  << "[Command] Client adress : " << inet_ntoa(info->address.sin_addr) << ":" << ntohs(info->address.sin_port) << "."                << std::endl;
                        if(info->mirror != NULL)
                        std::cout << "[Command] Client mirror : " << inet_ntoa(info->mirror->address.sin_addr) << ":" << ntohs(info->mirror->address.sin_port) << "." << std::endl;

                        return;
                    }
                }
            }

            else
            {
                std::cout << "[Command]<help> info [type] [client name]"                                      << std::endl;
                std::cout << "[Command]<help> Display information about given connection."                    << std::endl;
                std::cout << "[Command]<help> Type might be :"                                                << std::endl;
                std::cout << "[Command]<help>   - 'server' : displays information about this server."         << std::endl;
                std::cout << "[Command]<help>   - 'client' : displays information about given active client." << std::endl;
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
                std::cout << "[Command]<help> sendfile [client name] [file path]" << std::endl;
                std::cout << "[Command]<help> Send given file to given client."   << std::endl;
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
                    std::cout << "[Command] Can't initialize new client connection (adress='" << adress << "', port=" << port << ")." << std::endl;
            }

            else
            {
                std::cout << "[Command]<help> openclient [IP adress] [port]" << std::endl;
                std::cout << "[Command]<help> Open a new connection to given adress and port." << std::endl;
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
    }
}

void bytes_callback(const std::string& name, size_t current, size_t total)
{
    std::cout << "\r " << name << " : ";
    std::cout << current << " \\ " << total << "bytes";
    std::cout << " |";

    size_t chunk_total = 30;
    size_t sz_for_one  = total / chunk_total;
    size_t chunk_num   = current / sz_for_one;
    size_t blanck_num  = chunk_total - chunk_num;

    for(size_t i = 0; i < chunk_num; ++i)
        std::cout << "#";
    for(size_t i = 0; i < blanck_num; ++i)
        std::cout << " ";

    std::cout << "| ";
    size_t perc = (100 * chunk_num) / chunk_total;
    std::cout << perc << "%";
}

void display_help()
{
    std::cout << "GangTella is a free communication Project based on The Gang ideas by Luk2010." << std::endl;
    std::cout << "This program is FREE SOFTWARE and is distributed with NO WARRANTY. If you have any kind of problems with it, "
              << "you can send a mail to 'alain.ratatouille@gmail.com' (for suggestions it is the same adress :) ) . " << std::endl
              << "Uses : gangtella [options]" << std::endl
              << "Options : " << std::endl
              << " --s-port      : Specify a custom port for the Server."             << std::endl
              << "                 Default is 8377."                                  << std::endl
              << " --s-name      : Specify a custom name for the Server. This name "  << std::endl
              << "                 shown to every one who connect to this server."    << std::endl
              << " --c-adress    : Specify the IP adress for the automated"           << std::endl
              << "                 created client. Default is 127.0.0.1 (for test)."  << std::endl
              << " --c-port      : Specify a port for the automated created client."  << std::endl
              << "                 Default is 8378."                                  << std::endl
              << " --no-client   : Specify the program not to create a client at the" << std::endl
              << "                 beginning. This option is cool when you do not "   << std::endl
              << "                 test the program."                                 << std::endl
              << " --max-clients : Specify a max number of clients. Default is 10."   << std::endl
              << " --max-buffer  : Specify the Maximum buffer size for a packet. "    << std::endl
              << "                 Default is 1096."                                  << std::endl
              << " --help        : Show this text."                                   << std::endl;

    std::cout << "License : " << std::endl
              << "GangTella  Copyright (C) 2014  Luk2010" << std::endl
              << "This program comes with ABSOLUTELY NO WARRANTY." << std::endl
              << "This is free software, and you are welcome to redistribute it" << std::endl
              << "under certain conditions." << std::endl;
}

int main(int argc, char* argv[])
{
    std::cout << "GangTella v." << GANGTELLA_VERSION << "."  << std::endl;

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
    }

#ifdef GULTRA_DEBUG
    std::cout << "[Main] Server Name   = '" << server_name << "'." << std::endl;
    std::cout << "[Main] Server Port   = '" << server_port << "'." << std::endl;
    if(with_client) {
    std::cout << "[Main] Client Adress = '" << client_adress << "'." << std::endl;
    std::cout << "[Main] Client Port   = '" << client_port << "." << std::endl;
    }

    std::cout << "[Main] Server Max Client = '" << server_max_clients << "'." << std::endl;
    std::cout << "[Main] Server Max Buffer = '" << server_max_bufsize << "'." << std::endl;

#endif // GULTRA_DEBUG

    server_create(&server, server_name);
    server_initialize(&server, server_port, server_max_clients);
    server_setsendpolicy(&server, Gangtella::SP_CRYPTED);
#ifndef GULTRA_DEBUG
    server_setbytesreceivedcallback(&server, bytes_callback);
    server_setbytessendcallback(&server, bytes_callback);
#endif // GULTRA_DEBUG

    // Creation thread serveur
    std::cout << "[Main] Creating Server thread." << std::endl;
    if(server_launch(&server) != GERROR_NONE)
    {
        std::cerr << "[Main] Couldn't launch server !!! Aborting." << std::endl;
        return 0;
    }

    // Waiting for server to be done
    while(server.started == false)
        usleep(2000);

    // Creation du client de test
    if(with_client)
    {
        std::cout << "[Main] Initializing client." << std::endl;
        client_t* tmp = nullptr; server_init_client_connection(&server, tmp, client_adress.c_str(), client_port);
    }

    // Waiting for client to be done
    usleep(2000);

    std::string tmp;
    while(1)
    {
        char buf[server_max_bufsize];
        std::cout << ":> ";
        std::cin.getline(buf, server_max_bufsize - 1);
        tmp = buf;
        if(tmp == "exit")
        {
            std::cout << "[Main] Exiting." << std::endl;
            pthread_cancel(server.thread);
            server_destroy(&server);
            break;
        }
        else
        {
            treat_command(tmp);
        }
    }

    std::cout << "[Main] Goodbye." << std::endl;
    return 0;
}
