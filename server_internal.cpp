/*
 File        : server_internal.cpp
 Description : Defines some internal server method.
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

#include "server.h"
#include "server_intern.h"

GBEGIN_DECL

#define server_access() gthread_mutex_lock(&server->mutex)
#define server_stopaccess() gthread_mutex_unlock(&server->mutex)

/** @brief Find the index of a client. */
int server_find_client_index_private_(server_t* cserver, const std::string& name)
{
    gthread_mutex_lock(&cserver->mutex);
    for(unsigned int i = 0; i < cserver->clients.size(); ++i)
    {
        if(cserver->clients[i].name == name)
        {
            gthread_mutex_unlock(&cserver->mutex);
            return i;
        }
    }
    gthread_mutex_unlock(&cserver->mutex);
    return -1;
}

client_t* server_create_client_thread_loop(server_t* server, client_t* client)
{
    pthread_t thread_client;
    pthread_create(&thread_client, 0, server_client_thread_loop, (void*) client);
    
    gthread_mutex_lock(&server->mutex);
    client->server_thread.thethread = thread_client;
    gthread_mutex_unlock(&server->mutex);
    
    return client;
}

/** @brief Create the home page. */
std::string server_http_compute_home(server_t* server)
{
    std::string homepage;
    std::stringstream hp(homepage);
    hp << "<!DOCTYPE html>"
    << "<html>"
    << "  <head>"
    << "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"> "
    << "    <title>Server " << server->name << " Home</title>"
    << "  </head>"
    << "  <body>"
    << "    <h1>" << server->name << " Home</h1>";
    if(globalsession.user)
        hp << "    <p>Current user logged : " << globalsession.user->name << ".</p>";
    hp << "  </body>"
    << "</html>";
    return hp.str();
}

std::string server_http_get_page(server_t* server, HttpRequestPacket* packet)
{
    std::string reqraw(packet->request);
    std::string page_needed("");
    if(!reqraw.empty())
    {
        for(std::string::const_iterator it = reqraw.begin(); it != reqraw.end(); ++it)
        {
            if(*(it+0) == 'G' &&
               *(it+1) == 'E' &&
               *(it+2) == 'T')
            {
                it++; it++; it++;
                
                while(*it == ' ') it++;
                while(*it != ' ') {
                    page_needed += *it;
                    it++;
                }
            }
        }
        
        if(page_needed == "/" || page_needed == "/home.html")
        {
            return server_http_compute_home(server);
        }
    }
    
    return std::string("Bad Request !");
}

/** @brief Generate a new id for given server. */
uint32_t server_generate_new_id(server_t* cserver)
{
    static uint32_t ret2 = 1;
    uint32_t ret;
    if(!cserver)
        ret = 0;
    else
    {
        // Case 1 : find empty slots in mapped connections.
        for(ClientsIdMap::const_iterator it = cserver->client_by_id.begin(); it != cserver->client_by_id.end(); it++)
        {
            if(it->second == nullptr) {
                ret = it->first;
                break;
            }
        }
        
        // Case 2 : return the next connection slot
        ret = ret2;
        ret2++;
    }
    return ret;
}

struct accepting_t
{
    server_t* server;
    int csock;
    SOCKADDR_IN csin;
};

void* accepting_thread_loop(void* data)
{
    server_t* server = reinterpret_cast<accepting_t*>(data)->server;
    int csock = reinterpret_cast<accepting_t*>(data)->csock;
    SOCKADDR_IN csin = reinterpret_cast<accepting_t*>(data)->csin;
    free(data);
    
    cout << "[Server] Receiving new Client connection." << endl;
    Packet* pclient = receive_client_packet(csock);
    if(!pclient)
    {
        cout << "[Server] Client disconnected before establishing connection." << endl;
        return nullptr;
    }
    else
    {
        
        if(pclient->m_type == PT_CLIENT_INFO)
        {
#ifdef GULTRA_DEBUG
            cout << "[Server] Getting infos from new client." << endl;
#endif // GULTRA_DEBUG
            
            server_access();
            {
                server->status = SS_ADDINGCLIENT;
            }
            server_stopaccess();
            
            ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(pclient);
            
#ifdef GULTRA_DEBUG
            cout << "[Server] ID     = '" << cip->info.id     << "'." << endl;
            cout << "[Server] IDret  = '" << cip->info.idret  << "'." << endl;
            cout << "[Server] Name   = '" << cip->info.name        << "'." << endl;
            cout << "[Server] S Port = '" << cip->info.s_port << "'." << endl;
#endif // GULTRA_DEBUG
            
            // If client send PT_CLIENT_INFO, this is a demand to create in our server a new client_t structure.   (idret == ID_CLIENT_INVALID)
            //                           OR   this is a demand to complete an already existant client_t structure. (idret != ID_CLIENT_INVALID)
            
            if(cip->info.idret == ID_CLIENT_INVALID)
            {
                clientptr_t new_client = nullptr;
                if(client_alloc(&new_client, cip->info.id, nullptr, server) != GERROR_NONE)
                {
                    // If we can't allocate new structure, notifiate the user.
                    cout << "[Server] Failure in request 'SS_ADDINGCLIENT' : can't allocate client structure." << endl;
                    
                }
                
                new_client->name.append(cip->info.name);
                new_client->sock    = csock;
                new_client->address = csin;
                buffer_copy(new_client->pubkey, cip->info.pubkey);
                
                // We create also the mirror connection
                new_client->mirror         = new client_t;
                new_client->mirror->id     = server_generate_new_id(server);
                new_client->mirror->name   = server->name;
                new_client->mirror->server = (void*) server;
                new_client->mirror->mirror = nullptr;
                
                // We create the connection
                if(client_create(new_client->mirror, inet_ntoa(csin.sin_addr), cip->info.s_port) != GERROR_NONE)
                {
                    cout << "[Server] Can't mirror connection to client '" << cip->info.name << "'." << endl;
                    delete new_client->mirror;
                    return nullptr;
                }
                
                // We confirm the client-server that everything is alright
                client_info_t info;
                info.id     = new_client->mirror->id;
                info.s_port = server->port;
                info.idret  = new_client->id;
                strcpy(info.name, new_client->mirror->name.c_str());
                buffer_copy(info.pubkey, *(server->pubkey));
                
                client_info_t serialized = serialize<client_info_t>(info);
                if(client_send_packet(new_client->mirror, PT_CLIENT_INFO, &serialized, sizeof(serialized)) != GERROR_NONE)
                {
                    cout << "[Server] Can't send packet 'PT_CLIENT_INFO' to client '" << new_client->name << "'." << endl;
                    
                    // We so close the connection
                    client_close(new_client->mirror, true);
                    delete new_client->mirror;
                    return nullptr;
                }
                
                gthread_mutex_lock(&server->mutex);
                {
                    // Registering in the server
                    server->clients.push_back(*new_client);
                    server->client_by_id[new_client->mirror->id] = & (server->clients.at(server->clients.size() - 1));
                }
                gthread_mutex_unlock(&server->mutex);
                
                client_t* cclient = server->client_by_id[new_client->mirror->id];
                cclient->established = true;
                
                // We now send the PT_CONNECTION_ESTABLISHED packet and create the client thread.
                server_create_client_thread_loop(server, cclient);
                server->client_send(cclient->mirror, PT_CLIENT_ESTABLISHED, NULL, 0);
                
                // If everything is alright, we can tell user
                cout << "[Server] New Client connected (name = '" << cclient->name << "', id = '" << cclient->mirror->id << "')." << endl;
                
                // As client is valid, we can save it to the database.
                //if(user_database_isloaded())
                //{
                /*dbclient_t dbc;
                 dbc.ip   = std::string(inet_ntoa(csin.sin_addr));
                 dbc.port = std::to_string(cip->info.s_port);
                 globalsession.user->clients.push_back(dbc);*/
                //}
            }
            
            else
            {
                // We retrieve the client
                client_t* new_client = server->client_by_id[cip->info.idret];
                new_client->id      = cip->info.id;
                new_client->name.append(cip->info.name);
                new_client->sock    = csock;
                new_client->address = csin;
                new_client->server  = (void*) server;
                buffer_copy(new_client->pubkey, cip->info.pubkey);
                
#ifdef GULTRA_DEBUG
                cout << "[Server] Received Public Key from client '" << new_client->name << "' : " << endl;
                cout << std::string(reinterpret_cast<const char*>(new_client->pubkey.buf), new_client->pubkey.size) << endl;
#endif // GULTRA_DEBUG
                
                // Once complete we create the thread
                server_create_client_thread_loop(server, new_client);
                
                // Now the pointed client should send us a PT_CLIENT_ESTABLISHED packet.
            }
            
        }
        else if(pclient->m_type == PT_CLIENT_NAME)
        {
            cout << "[Server] Packet 'PT_CLIENT_NAME' is deprecated. Please tell your client to update his GangTella application." << endl;
            return nullptr;
        }
        
        // Client can also send an http request
        else if(pclient->m_type == PT_HTTP_REQUEST)
        {
            HttpRequestPacket* request = reinterpret_cast<HttpRequestPacket*>(pclient);
            
            // Compute page
            std::string buf = server_http_get_page(server, request);
            // Commpute header
            std::string header;
            std::stringstream hp(header);
            hp << "HTTP/1.0 200 OK\r\n";
            hp << "Server: Apache\r\n";
            hp << "Content-lenght: " << buf.size() << "\r\n";
            hp << "Content-Type: text/html\r\n";
            hp << "\r\n";
            hp << buf;
            
            send(csock, hp.str().c_str(), hp.str().size(), 0);
            //                send(csock, buf.c_str(),      buf.size(),      0);
            closesocket(csock);
            
            delete request;
        }
        
        else
        {
            std::cerr << "Client didn't send correct packet ! ( " << (int) pclient->m_type << " )." << endl;
            //                delete pclient;
            return nullptr;
        }
    }
    
    return nullptr;
}

void server_launch_accepting_thread(server_t* server, int csock, SOCKADDR_IN csin)
{
    accepting_t* data = (accepting_t*) malloc(sizeof(accepting_t));
    data->server = server;
    data->csock = csock;
    data->csin = csin;
    
    pthread_t mthread;
    pthread_create(&mthread, NULL, accepting_thread_loop, data);
}

void server_launch_minimal(server_t* server, void* (*command)(void*))
{
    pthread_t mthread;
    pthread_create(&mthread, nullptr, command, server);
}

GEND_DECL