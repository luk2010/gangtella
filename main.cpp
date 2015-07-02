/*
    File        : main.cpp
    Description : Creates the server and treats commands.
*/

/*
    GangTella Project
    Copyright (C) 2014 - 2015  Luk2010

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
#include "database.h"
#include "serverlistener.h"

using namespace Gangtella;

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
    
    bool cancel_command = false;

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
                        client_send_packet(to, PT_CLIENT_MESSAGE, command.c_str() + 11, command.size() - 11);
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
            async_command_launch(CMD_INFO, args, &server);
        }


        else if(args[0] == "sendfile")
        {
            async_command_launch(CMD_SENDFILE, args, &server);
        }


        else if(args[0] == "openclient")
        {
            async_command_launch(CMD_OPENCLIENT, args, &server);
        }

        else if(args[0] == "closeclient")
        {
            async_command_launch(CMD_CLOSECLIENT, args, &server);
        }

        else if(args[0] == "userlogin")
		{
			// This is a beta test
			async_command_launch(CMD_USERLOGIN, args, &server);
		}

		else if(args[0] == "userunlog")
		{
			// This is a beta test
			async_command_launch(CMD_USERUNLOG, args, &server);
		}

		else if(args[0] == "userinit")
		{
			// This is a beta test
			async_command_launch(CMD_USERINIT, args, &server);
		}

		else if(args[0] == "usercheck")
		{
			async_command_launch(CMD_USERCHECK, args, &server);
		}

        else if(args[0] == "version")
        {
            async_command_launch(CMD_VERSION, args, globalsession.server);
        }
        
        else
        {
            cancel_command = true;
        }
    }
    
    if(cancel_command == true)
        globalsession._treatingcommand = false;

    console_last_command = command;
}

// Displays a cool loading bar on the screen.
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
    cout << "GangTella is a free server & client connector to the Gang Network." << endl;
    cout << "This program is FREE SOFTWARE and is distributed with NO WARRANTY." << endl;
    cout << "If you have any kind of problems with it, " << endl;
	cout << "you can send a mail to 'alain.ratatouille@gmail.com' (for suggestions it is the same adress :) ) . " << endl; cout
	     << "Uses    : gangtella [options]" << endl; cout
		 << "Options : " << endl; cout

    << "== Important args (user, password, database) ==" << endl; cout

    << " --username    : Uses given username to connect. You should also provide" << endl; cout
    << "                 your password using --userpass." << endl; cout
    << " --userpass    : Uses given password, for given username." << endl; cout
    << " --dbname      : Uses given database. You should provide password with --dbpass." << endl; cout
    << " --dbpass      : Uses given password according to --dbname argument." << endl; cout

    << "== Low-level args ==" << endl; cout

    << " --s-port      : Specify a custom port for the Server."             << endl; cout
    << "                 Default is 8377."                                  << endl; cout
    << " --s-name      : Specify a custom name for the Server. This name "  << endl; cout
    << "                 is shown to every one who connect to this server." << endl; cout
    << " --max-clients : Specify a max number of clients. Default is 10."   << endl; cout
    << " --max-buffer  : Specify the Maximum buffer size for a packet. "    << endl; cout
    << "                 Default is 1096."                                  << endl; cout
    << " --no-ssl      : Begins a session without OpenSSL (at your own risk.)" << endl; cout
    << " --logfile-info : Sets the file to redirect info log." << endl; cout
    << " --logfile-warn : Sets the file to redirect warning log." << endl; cout
    << " --logfile-err  : Sets the file to redirect error log." << endl; cout

    << "== Others args ==" << endl; cout

    << " --help        : Show this text."                                   << endl; cout
    << " --usr-help    : Show a help text on how to connect to the Network."<< endl; cout
    << " --version     : Show the version number."                          << endl; cout
    << " --test-unit-a : Launch the program as Test Unit A (s-port=8888, dbname=a," << endl; cout
    << "                 dbpass=a, s-name=a, username=a, userpass=a, log=a.log)" << endl; cout
    << " --test-unit-b : Launch the program as Test Unit B (s-port=7777, dbname=b," << endl; cout
    << "                 dbpass=b, s-name=b, username=b, userpass=b, log=b.log)" << endl;

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

class TestServerListener : public ServerListener
{
public:
    
    ~TestServerListener() { }
    
    void onServerStarted(const ServerStartedEvent* e) {
        gnotifiate_info("[TestServerListener] Server started !");
    }
    void onServerStopped(const ServerStoppedEvent* e) {
        gnotifiate_info("[TestServerListener] Server stopped !");
    }
    void onClientCompleted(const ServerClientCompletedEvent* e) {
        gnotifiate_info("[TestServerListener] Client '%s' completed !", e->client->name.c_str());
    }
    void onClientClosed(const ServerClientClosedEvent* e) {
        gnotifiate_info("[TestServerListener] Client '%s' closed !", e->client->name.c_str());
    }
};

int main(int argc, char* argv[])
{
    // Argues

    server.args.port          = 8378;
    server.args.name          = "Default";
    server.args.maxclients    = 10;
    server.args.maxbufsize    = 1024;
    server.args.withssl       = true;

    std::string username("");
    std::string ncuserpass("");
    std::string dbname("");
    std::string ncdbpass("");
    
    FILE* loginfo = nullptr;
    FILE* logwarn = nullptr;
    FILE* logerr  = nullptr;

    for(int i = 0; i < argc; ++i)
    {
        if(std::string("--s-port") == argv[i])
        {
            server.args.port = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--s-name") == argv[i])
        {
            server.args.name = argv[i+1];
            i++;
        }
        else if(std::string("--max-clients") == argv[i])
        {
            server.args.maxclients = atoi(argv[i+1]);
            i++;
        }
        else if(std::string("--max-buffer") == argv[i])
        {
            server.args.maxbufsize = atoi(argv[i+1]);
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
        else if(std::string("--no-ssl") == argv[i])
        {
            server.args.withssl = false;
        }
        else if(std::string("--username") == argv[i])
        {
            username = argv[i+1];
            i++;
        }
        else if(std::string("--userpass") == argv[i])
        {
            ncuserpass = argv[i+1];
            i++;
        }
        else if(std::string("--dbname") == argv[i])
        {
            dbname = argv[i+1];
            i++;
        }
        else if(std::string("--dbpass") == argv[i])
        {
            ncdbpass = argv[i+1];
            i++;
        }
        
        else if(std::string("--logfile-info") == argv[i])
        {
            loginfo = fopen(argv[i+1], "w");
        }
        else if(std::string("--logfile-warn") == argv[i])
        {
            logwarn = fopen(argv[i+1], "w");
        }
        else if(std::string("--logfile-err") == argv[i])
        {
            logerr = fopen(argv[i+1], "w");
        }
        
        // If we have --test-unit option set, we overwrite every options.
        if(std::string("--test-unit-a") == argv[i])
        {
            server.args.port = 8888;
            server.args.name = "A";
            dbname           = "test-unit-a.db";
            ncdbpass         = "a";
            username         = "a";
            ncuserpass       = "a";
            
            loginfo = fopen("a.info.log", "w");
            logwarn = fopen("a.warn.log", "w");
            logerr  = fopen("a.err.log", "w");
        }
        else if(std::string("--test-unit-b") == argv[i])
        {
            server.args.port = 7777;
            server.args.name = "B";
            dbname           = "test-unit-b.db";
            ncdbpass         = "b";
            username         = "b";
            ncuserpass       = "b";
            
            loginfo = fopen("b.info.log", "w");
            logwarn = fopen("b.warn.log", "w");
            logerr  = fopen("b.err.log", "w");
        }
    }
    
    // Set the logging files.
    gnotifiate_setloglevelfile(1, logerr  ? logerr  : stderr);
    gnotifiate_setloglevelfile(2, logwarn ? logwarn : stderr);
    gnotifiate_setloglevelfile(3, loginfo ? loginfo : stdout);
    
    gnotifiate_info("GangTella v.%s.", GANGTELLA_VERSION);
    
    // Register our listener.
    TestServerListener* tsl = new TestServerListener;
    server.addListener(tsl);

    // Initialize encryption unit.

    if(server.args.withssl) {
        if(encryption_init() != GERROR_NONE) {
            gnotifiate_error("[Main] Can't initialize OpenSSl.");
            exit(GERROR_ENCRYPT_NOSSL);
        }
    }

    if(server.args.withssl == false) {
        gnotifiate_error("[Main] Sorry, uncrypted sessions are not allowed anymore.");
        exit(GERROR_ENCRYPT_NOSSL);
    }

    // Check the args. Ask for them if we do not have. (database)

    if(dbname.empty())
    {
        cout << "[Main] No database provided ! Try to use default one ? [Y/n]" << endl;
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);

        char buf[server.args.maxbufsize];
        std::cin.getline(buf, server.args.maxbufsize - 1);

        std::string answer(buf);
        if(answer != "n" && answer != "N") {
            dbname = "default_database.db";
        }
        else {
            cout << "[Main] Please specify database path : " << endl;
            cout << ":>"; gthread_mutex_unlock(&__console_mutex);

            char buf2[server.args.maxbufsize];
            std::cin.getline(buf2, server.args.maxbufsize - 1);

            answer = buf2;
            if(answer.empty()) {
                cout << "[Main] No database provided !! Exiting." << endl;
                exit(GERROR_USR_NODB);
            }

            dbname = answer;
        }
    }

    if(ncdbpass.empty())
    {
        cout << "[Main] Please provide password for database '" << dbname << "' : " << endl;
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);

        std::string ncpass = getpass();
        if(ncpass.empty()) {
            cout << "[Main] No password provided. Exiting." << endl;
            exit(GERROR_USR_NODBPASS);
        }

        ncdbpass = ncpass;
    }

    // Now opens the database.

    database_t* database = nullptr;
    if(database_load(database,dbname, ncdbpass) != GERROR_NONE) {
        cout << "[Main] Can't load database '" << dbname << "'. Exiting." << endl;
        exit(GERROR_USR_NODB);
    }

    // Now check the user input.

    user_t* user = new user_t();
    //user->lkey = 0;
    //user->liv = 0;

    if(username.empty())
    {
        cout << "[Main] No username provided ! Please type username : " << endl;
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);

        char buf[server.args.maxbufsize];
        std::cin.getline(buf, server.args.maxbufsize - 1);

        std::string answer(buf);
        if(answer.empty()) {
            exit(GERROR_NOUSER);
        }

        username = answer;
    }

    database_user_t* dbuser = database_find_user(database, username);
    if(!dbuser)
    {
        cout << "[Main] User '" << username << "' does not exist in database '" << dbname << "'." << endl;
        cout << "[Main] Do you want to create it ? [Y/n]" << endl;
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);

        char buf[server.args.maxbufsize];
        std::cin.getline(buf, server.args.maxbufsize - 1);

        std::string answer = buf;
        if(answer.empty()) {
            exit(GERROR_NOUSER);
        }

        if(answer == "n" || answer == "N") {
            exit(GERROR_NOUSER);
        }

        if(ncuserpass.empty())
        {
            cout << "[Main] Please provide password for user '" << username << "' : " << endl;
            cout << ":> "; gthread_mutex_unlock(&__console_mutex);

            std::string ncpass = getpass();
            if(ncpass.empty()) {
                cout << "[Main] No password provided. Exiting." << endl;
                exit(GERROR_NOUSERPASS);
            }

            ncuserpass = ncpass;
        }

        // Create the new user
        dbuser = database_create_user(database, username, ncuserpass);
    }

    user = dbuser;

    // Check the password

    if(ncuserpass.empty())
    {
        cout << "[Main] Please provide password for user '" << username << "' : " << endl;
        cout << ":> "; gthread_mutex_unlock(&__console_mutex);

        std::string ncpass = getpass();
        if(ncpass.empty()) {
            cout << "[Main] No password provided. Exiting." << endl;
            exit(GERROR_NOUSERPASS);
        }

        ncuserpass = ncpass;
    }

    std::string tmp1(user->m_key->buf);
    std::string tmp2(user->m_iv->buf);

    if(!Encryption::user_check_password(tmp1, tmp2, ncuserpass.c_str(), ncuserpass.size())) {
        cout << "[Main] Wrong password. Exiting." << endl;
        exit(GERROR_USR_BADPSWD);
    }

    // Now, we have a valid session.

    globalsession.database = database;
    globalsession.user     = user;
    globalsession.server   = &server;

    // In debug mode, we display some usefull informations for the running user.

#ifdef GULTRA_DEBUG

    cout << "[Main] Server Name   = '" << server.args.name << "'." << endl;
    cout << "[Main] Server Port   = '" << server.args.port << "'." << endl;
    cout << "[Main] Server Max Client = '" << server.args.maxclients << "'." << endl;
    cout << "[Main] Server Max Buffer = '" << server.args.maxbufsize << "'." << endl;

#endif // GULTRA_DEBUG

    // Creating the server to accept connections.

    server_create();
    server_initialize();

    // User always should use the Crypted version, but at his own risk he can use the
    // noncrypted one. Thought other server may require that yours should be using
    // crypting.
    // [Note] 19/04/2015 : No uncrypted sessions allowed. Program exits before creating
    // an uncrypted server.

    if(server.args.withssl) {
        server_setsendpolicy(&server, Gangtella::SP_CRYPTED);
    }
    else {
        server_setsendpolicy(&server, Gangtella::SP_NORMAL);
    }

    // On debug mode, too much informations are displayed at screen so we don't call
    // these callbacks. But on release mode, these are so cool ;).

#ifndef GULTRA_DEBUG
    server_setbytesreceivedcallback(&server, bytes_callback);// Receiving file.
    server_setbytessendcallback    (&server, bytes_callback);// Sending file.
#endif // GULTRA_DEBUG

    // Create the server thread and launch it.
    // If the server can't start, we abort the program.

    cout << "[Main] Creating Server thread." << endl;
    if(server_launch(&server) != GERROR_NONE)
    {
        cout << "[Main] Couldn't launch server !!! Aborting." << endl;
        exit(EXIT_FAILURE);
    }

    if(server_wait_status(&server, SS_STARTED, 300) != GERROR_NONE)
    {
        cout << "[Main] Could not start server ! Aborting." << endl;
        exit(EXIT_FAILURE);
    }

    globalsession._treatingcommand = false;
    std::string tmp;
    while(1)
    {
        char buf[server.args.maxbufsize];
        cout << "@" << (const char*) globalsession.user->m_name->buf << ":> "; gthread_mutex_unlock(&__console_mutex);
        std::cin.getline(buf, server.args.maxbufsize - 1);
        tmp = buf;
        if(tmp == "exit")
        {
            cout << "[Main] Exiting." << endl;
            server_stop(&server);
            server_destroy(&server);
            break;
        }
        else
        {
            globalsession._treatingcommand = true;
            treat_command(tmp);
            while(globalsession._treatingcommand);
        }
    }
    
    cout << "[Main] Saving database '" << globalsession.database->m_name->buf << "'." << endl;
    database_save(globalsession.database);
    
    // Cleaning our listener
    server.removeListener(tsl);
    delete tsl;
    
    // Clean the log system
    if(loginfo)
        fclose(loginfo);
    if(logwarn)
        fclose(logwarn);
    if(logerr)
        fclose(logerr);

    cout << "[Main] Goodbye." << endl;
    return 0;
}
