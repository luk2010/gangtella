/*
    File : server.cpp
    Description : Implements server functions.
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
#include "server.h"
#include "packet.h"
#include "commands.h"

GBEGIN_DECL

#define ID_CLIENT_INVALID 0

void* server_thread_loop (void*);

/** @brief Find the index of a client. */
int server_find_client_index_private_(server_t* server, const std::string& name)
{
    gthread_mutex_lock(&server->mutex);
    for(unsigned int i = 0; i < server->clients.size(); ++i)
    {
        if(server->clients[i].name == name)
        {
            gthread_mutex_unlock(&server->mutex);
            return i;
        }
    }
    gthread_mutex_unlock(&server->mutex);
    return -1;
}

/** @brief Generate a new id for given server. */
uint32_nt server_generate_new_id(server_t* server)
{
    static uint32_t ret2 = 1;
    uint32_nt ret;
    if(!server)
        ret.data = 0;
    else
    {
        // Case 1 : find empty slots in mapped connections.
        for(ClientsIdMap::const_iterator it = server->client_by_id.begin(); it != server->client_by_id.end(); it++)
        {
            if(it->second == nullptr) {
                ret.data = it->first;
                break;
            }
        }

        // Case 2 : return the next connection slot
        ret.data = ret2;
        ret2++;
    }
    return ret;
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
       if(server->logged)
	hp << "    <p>Current user logged : " << server->logged_user.name << ".</p>";
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

/** @brief Initialize the default parameters of the server_t structure.
 *
 *  @note A RSA assymetric key is created during the process. The public key
 *  is sent to new clients to decrypt the packets.
 *
 *  @param server    : A pointer to the server structure.
 *  @param disp_name : The name of this server. This name will be displayed
 *  on the other server. It must not be confused with the connection ID, wich
 *  caracterize a client connection.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
**/
gerror_t server_create(server_t* server, const std::string& disp_name)
{
    if(!server)
        return GERROR_BADARGS;

#ifdef GULTRA_DEBUG
    cout << "[Server] Creating server at adress : '" << (uint32_t) server << "'." << endl;
    cout << "[Server] Name = '" << disp_name << "'." << endl;
#endif // GULTRA_DEBUG

    server->mutex   = PTHREAD_MUTEX_INITIALIZER;
    server->started = false;
    server->name    = disp_name;
    server->crypt   = nullptr;

#ifdef GULTRA_DEBUG
    cout << "[Server] Creating RSA encryption key." << endl;
#endif // GULTRA_DEBUG

    gerror_t err = Encryption::encryption_create(server->crypt);

#ifdef GULTRA_DEBUG
    cout << "[Server] encryption_create return '" << gerror_to_string(err) << "'." << endl;
#endif // GULTRA_DEBUG

    server->pubkey       = new buffer_t;
    server->pubkey->size = 0;
    if( (err = Encryption::encryption_get_publickey(server->crypt, server->pubkey)) != GERROR_NONE)
    {
#ifdef GULTRA_DEBUG
        cout << "[Server] Public Key Error : '" << gerror_to_string(err) << "'." << endl;
#endif // GULTRA_DEBUG
        delete server->pubkey;
    }

    // We set it to normal for now.
    server_setsendpolicy(server, SP_NORMAL);

#ifdef GULTRA_DEBUG
    cout << "[Server] Key lenght = " << server->pubkey->size << "." << endl;
    cout << "[Server] Public key = '" << std::string(reinterpret_cast<char*>(server->pubkey->buf), server->pubkey->size) << "'." << endl;
#endif // GULTRA_DEBUG

	cout << "[Server] Setting up database." << endl;
	
	std::ifstream indb("users.gtl");
	if(!indb)
	{
		cout << "[Server] Can't find defaut database. Creating new." << endl;
		udatabase = new user_db_t;
		udatabase->autosave = true;
		udatabase->dbfile   = "users.gtl";
		udatabase->dbname   = "default";
	}
	else
	{
		indb.close();
		user_database_load("users.gtl");
	}
	
	server->logged = false;

    cout << "[Server] Correctly created." << endl;
    cout << "[Server] RSA size = " << RSA_size(server->crypt->keypair) << endl;

    return GERROR_NONE;
}

/** @brief Initialize a new server structure.
 *  @note This function assumes server is not null, and mutex and started
 *  are already initialized.
 *
 *  @param server     : A pointer to the server structure.
 *  @param port       : A valid port to set the server. Range is [0 - 65534].
 *  @param maxclients : The maximum number of clients that can be accepted by
 *  this server. Range is [0 - 256] generally, but you may extend it to
 *  size_t maximum value.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null or if maxclients is 0.
 *  - GERROR_INVALID_SOCKET if socket can't be initialized.
 *  - GERROR_INVALID_BINDING if socket can't be binded.
 *  - GERROR_INVALID_LISTENING if socket can't listen to port.
 *  On Windows :
 *  - GERROR_WSASTARTUP if WSA can't be started.
**/
int server_initialize(server_t* server, size_t port, int maxclients)
{
    if(!server)
        return GERROR_BADARGS;

    if(maxclients == 0)
    {
        cout << "[Server] Why initializing a server with 0 maximum clients ?!" << endl;
        return GERROR_BADARGS;
    }

#ifdef _WIN32

#ifdef GULTRA_DEBUG
    cout << "[Server] Starting WSA2.0." << endl;
#endif // GULTRA_DEBUG

    int err;
    WSAData wsadata;
    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(err == WSASYSNOTREADY)
    {
        cout << "[Server] Could not start Windows Socket : "
                  << "The underlying network subsystem is not ready for network communication." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAVERNOTSUPPORTED)
    {
        cout << "[Server] Could not start Windows Socket : "
                  << "The version of Windows Sockets support requested is not provided by this particular Windows Sockets implementation." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEINPROGRESS)
    {
        cout << "[Server] Could not start Windows Socket : "
                  << "A blocking Windows Sockets 1.1 operation is in progress." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEPROCLIM)
    {
        cout << "[Server] Could not start Windows Socket : "
                  << "A limit on the number of tasks supported by the Windows Sockets implementation has been reached." << endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEFAULT)
    {
        cout << "[Server] Could not start Windows Socket : "
                  << "The lpWSAData parameter is not a valid pointer." << endl;
        return GERROR_WSASTARTUP;
    }

#endif // _WIN32

    gthread_mutex_lock(&server->mutex);
    {

#ifdef GULTRA_DEBUG
        cout << "[Server] Initializing Server on port '" << port << "'." << endl;
#endif // GULTRA_DEBUG

        server->clients.reserve(maxclients);
        server->sock = socket(AF_INET, SOCK_STREAM, 0);

        if(server->sock == INVALID_SOCKET)
        {
            std::cerr << "[Server] Invalid server creation ! (Socket invalid)" << endl;
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_SOCKET;
        }

        SOCKADDR_IN sin;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(port);
        if(bind(server->sock, (SOCKADDR*) &sin, sizeof(sin) ) == SOCKET_ERROR)
        {
            std::cerr << "[Server] Invalid server creation ! (Can't bind socket on port : " << port << ".)" << endl;

            closesocket(server->sock);
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_BINDING;
        }

        if(listen(server->sock, maxclients) == SOCKET_ERROR)
        {
            std::cerr << "[Server] Invalid server creation ! (Can't listen to clients.)" << endl;

            closesocket(server->sock);
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_LISTENING;
        }

        cout << "[Server] Ready to listen on port '" << port << "'." << endl;
        server->started = true;
        server->port    = port;
    }
    gthread_mutex_unlock(&server->mutex);

    return GERROR_NONE;
}

/** @brief Launch the Server thread.
 *
 *  @param server : A pointer to the server structure.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *  - GERROR_THREAD_CREATION if thread cannot be created.
**/
gerror_t server_launch(server_t* server)
{
    if(!server)
        return GERROR_BADARGS;

#ifdef GULTRA_DEBUG
    cout << "[Server] Launching server thread." << endl;
#endif // GULTRA_DEBUG

    int ret = pthread_create(&server->thread, NULL, server_thread_loop, server);
    if(ret != 0)
        return GERROR_THREAD_CREATION;
    else
        return GERROR_NONE;
}

/** @brief Destroys this server and all his client connection.
 *
 *  @param server : A pointer to the server structure.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *  - GERROR_MUTEX_LOCK if mutex can't be locked.
 *  - GERROR_MUTEX_UNLOCK if mutex can't be unlocked.
 *  - GERROR_WSACLEANING if WSA can't be cleaned.
**/
gerror_t server_destroy(server_t* server)
{
    if(!server)
    {
#ifdef GULTRA_DEBUG
        cout << "[Server] Can't destroy null server." << endl;
#endif // GULTRA_DEBUG
        return GERROR_BADARGS;
    }

    if(!gthread_mutex_lock(&server->mutex))
        return GERROR_MUTEX_LOCK;

    for(unsigned int i = 0; i < server->clients.size(); ++i)
    {
        // TODO : find another way.
        pthread_cancel(server->clients[i].server_thread);
        ////////////////////////////////////////////////

        if(server->clients[i].sock != 0)
        {
            if(server->clients[i].mirror != NULL)
            {
                client_close(server->clients[i].mirror);
                delete server->clients[i].mirror;
                server->clients[i].mirror = 0;
            }

            closesocket(server->clients[i].sock);
        }
        
        if(server->clients[i].logged)
		{
			// We try to save the user if it has not already been saved.
			if(!user_is_loaded(server->clients[i].logged_user.name))
			{
				udatabase->users[server->clients[i].logged_user.name].name = server->clients[i].logged_user.name;
				udatabase->users[server->clients[i].logged_user.name].key  = server->clients[i].logged_user.key;
				udatabase->users[server->clients[i].logged_user.name].iv   = server->clients[i].logged_user.iv;
			}
		}
    }

    closesocket(server->sock);

    // Destroy the RSA structures
    if(server->pubkey)
    {
        delete server->pubkey;
        server->pubkey = nullptr;
    }
    if(server->crypt)
    {
        Encryption::encryption_destroy(server->crypt);
        server->crypt = nullptr;
    }

    // Destroy structures
    server->clients.clear();
    server->client_by_id.clear();
    server->started = false;

    int err = GERROR_NONE;

#ifdef _WIN32

#ifdef GULTRA_DEBUG
    cout << "[Server] Cleaning Windows Socket 2.0." << endl;
#endif // GULTRA_DEBUG

    int ret = WSACleanup();

    if(ret == WSANOTINITIALISED)
    {
        cout << "[Server] Could not clean Windows Socket : "
                  << "A successful WSAStartup call must occur before using this function." << endl;
        err = GERROR_WSACLEANING;
    }
    else if(ret == WSAENETDOWN)
    {
        cout << "[Server] Could not clean Windows Socket : "
                  << "The network subsystem has failed." << endl;
        err = GERROR_WSACLEANING;
    }
    else if(ret == WSAEINPROGRESS)
    {
        cout << "[Server] Could not clean Windows Socket : "
                  << "A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function." << endl;
        err = GERROR_WSACLEANING;
    }

#endif // _WIN32

	if(server->logged)
		user_destroy(server->logged_user);

	user_database_destroy();

    cout << "[Server] Server destroyed." << endl;

    if(!gthread_mutex_unlock(&server->mutex))
        return GERROR_MUTEX_UNLOCK;

    return err;
}

gerror_t server_setsendpolicy(server_t* server, int policy)
{
    if(policy > SP_CRYPTED || policy < SP_NORMAL || !server)
        return GERROR_BADARGS;

    if(policy == SP_NORMAL)
        server->client_send = client_send_packet;
    if(policy == SP_CRYPTED)
        server->client_send = client_send_cryptpacket;

    return GERROR_NONE;
}

gerror_t server_setbytesreceivedcallback(server_t* server, bytesreceived_t callback)
{
    if(!server)
        return GERROR_BADARGS;
    server->br_callback = callback;
    return GERROR_NONE;
}

gerror_t server_setbytessendcallback(server_t* server, bytessend_t callback)
{
    if(!server)
        return GERROR_BADARGS;
    server->bs_callback = callback;
    return GERROR_NONE;
}

/** @brief Receive a packet from given client and decrypt it if encrypted.
 *
 *  @param server : Pointer to the server_t object.
 *  @param client : Pointer to the client_t object.
 *
 *  @return
 *  - nullptr if packet can't be received or if packet can't be decrypted.
 *  - A Packet object that correspond to what the client send. @note You must delete
 *  this object yourself.
**/
Packet* server_receive_packet(server_t* server, client_t* client)
{
    Packet* pclient = receive_client_packet(client->sock);
    if(!pclient)
    {
        cout << "[Server] Invalid packet reception." << endl;
        if(server)
            server_end_client(server, client->name);
        else
            client_close(client);

        return NULL;
    }

    // If packet is an encrypted packet, we decrypt it and return
    // the final packet.
    if(pclient->m_type == PT_ENCRYPTED_INFO)
    {
        // We received encrypted data
#ifdef GULTRA_DEBUG
        cout << "[Server]{" << client->name << "} Receiving Encrypted data." << endl;
#endif // GULTRA_DEBUG

        // Verifying we have the public key
        if(client->pubkey.size > 0)
        {
            // Get the infos
            EncryptedInfoPacket* eip = reinterpret_cast<EncryptedInfoPacket*>(pclient);
            size_t chunk_size   = RSA_SIZE;                           // Size of one chunk
            size_t data_size    = chunk_size - 11;                    // Size fo one data chunk
            size_t chunk_num    = eip->info.cryptedblock_number.data; // Number of chunk
            size_t chunk_lastsz = eip->info.cryptedblock_lastsz.data; // Size of the last chunk
            buffer_t& pubkey    = client->pubkey;                     // Public key
            uint8_t ptype       = eip->info.ptype;                    // Type of the packet
            size_t tot_sz       = data_size * (chunk_num - 1) + chunk_lastsz; // Size of the packet data.

            // We have everything we need so destroy the EncryptedInfoPacket.
            delete eip;
            eip     = nullptr;
            pclient = nullptr;

            if(chunk_num != 0)
            {
                // Create the buffer to holds data
                unsigned char* data    = (unsigned char*) malloc(tot_sz);
                unsigned char* cptr    = data;
                unsigned char* endptr  = data + tot_sz;
                unsigned char* cbuffer = (unsigned char*) malloc(data_size);
                size_t         decrypted = 0;

                // Loop to decrypt data
                while(cptr != endptr)
                {
                    // Get the chunk packet
                    Packet* vchunk = receive_client_packet(client->sock);
                    if(!vchunk || vchunk->m_type != PT_ENCRYPTED_CHUNK)
                    {
                        cout << "[Server]{" << client->name << "} Can't receive Encrypted chunk !" << endl;
                        free(data);
                        free(cbuffer);
                        if(vchunk)
                            delete vchunk;

                        return nullptr;
                    }

                    // Get the encrypted packet
                    EncryptedChunkPacket* echunk = reinterpret_cast<EncryptedChunkPacket*>(vchunk);
                    // Decrypt data into buffer
                    int len = Encryption::decrypt(pubkey, cbuffer, echunk->chunk, chunk_size);
                    // Copy data
                    memcpy(cptr, cbuffer, len);

                    // Destroy chunk and iterate
                    cptr      += len;
                    decrypted += len;
                    delete vchunk;

                    // Infos
#ifdef GULTRA_DEBUG
                    cout << "[Server]{" << client->name << "} Decrypted " << decrypted << "/" << tot_sz << " bytes."  << endl;
#endif // GULTRA_DEBUG
                }

                // Destroy the buffer we don't need it anymore.
                free(cbuffer);

                // Create the packet
                Packet* vret = packet_choose_policy(ptype);
                // Interpret packet
                packet_interpret(ptype, vret, (data_t*) data, tot_sz);

                // Destroy data
                free(data);

                // Return the packet
                return vret;
            }

            else
            {
                Packet* cpacket = packet_choose_policy(ptype);
                packet_interpret(ptype, cpacket, 0, 0);
                return cpacket;

#ifdef GULTRA_DEBUG
                cout << "[Server]{" << client->name << "} Received Encrypted Packet." << endl;
#endif // GULTRA_DEBUG
            }
        }
        else
        {
            cout << "[Server]{" << client->name << "} Can't decrypt data without public key !" << endl;
            return nullptr;
        }
    }

    return pclient;
}

void* server_client_thread_loop(void* data)
{
    client_t* client = (client_t*) data;
    server_t* org    = (server_t*) client->server;

    while(1)
    {
    	client->idling  = true;
        Packet* pclient = server_receive_packet(org, client);
        client->idling  = false;

        if(!pclient || pclient->m_type == PT_CLIENT_CLOSING_CONNECTION)
        {
            // Client send PT_CLOSING_CONNECTION if it wants tis server to destroy the client object.
            // We close the socket, destroy the client but don't send any packet.

            uint32_t cid = ID_CLIENT_INVALID;
            if(client->mirror != NULL)
            {
                cid   = client->mirror->id.data;
                client_close(client->mirror, false);

                delete client->mirror;
                client->mirror = 0;
            }

            closesocket(client->sock);
            client->sock = 0;
            
            if(client->logged)
			{
				// We try to save the user if it has not already been saved.
				if(!user_is_loaded(client->logged_user.name))
				{
					udatabase->users[client->logged_user.name].name = client->logged_user.name;
					udatabase->users[client->logged_user.name].key  = client->logged_user.key;
					udatabase->users[client->logged_user.name].iv   = client->logged_user.iv;
				}
			}

            cout << "[Server]{" << client->name << "} Closed client." << endl;

            // Erasing client from vectors
            int cindex = server_find_client_index_private_(org, client->name);

            gthread_mutex_lock(&org->mutex);
            org->clients.erase(org->clients.begin() + cindex);
            if(cid != ID_CLIENT_INVALID)
                org->client_by_id[cid] = nullptr;
            gthread_mutex_unlock(&org->mutex);

            if(pclient)
                delete pclient;

            return NULL;
        }
        else if(pclient->m_type == PT_CLIENT_MESSAGE)
        {
            ClientMessagePacket* cmp = reinterpret_cast<ClientMessagePacket*>(pclient);
            std::string message = cmp->buffer;
            cout << "[Server]{" << client->name << "} " << message << endl;
            delete cmp;
        }
        else if(pclient->m_type == PT_CLIENT_ESTABLISHED)
        {
            cout << "[Server]{" << client->name << "} Established connection." << endl;
            client->established = true;
            delete pclient;
            
            // As client is valid, we can save it to the database.
			if(user_database_isloaded())
			{
				dbclient_t dbc;
				dbc.ip   = std::string(inet_ntoa(client->address.sin_addr));
				dbc.port = std::to_string(ntohs(client->mirror->address.sin_port));
				udatabase->clients.push_back(dbc);
			}
        }

		else if(pclient->m_type == PT_USER_INIT)
		{
			cout << "[Server]{" << client->name << "} Initializing user." << endl;
			UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(pclient);
			cout << "[Server]{" << client->name << "} Connected user '" << uip->data.name << "'." << endl;
			
			if(org->logged)
			{
				// Verify that user isn't already accepted.
				if(udatabase->users.find(uip->data.name) != udatabase->users.end())
				{
#ifndef GULTRA_DEBUG
					cout << "[Server]{" << client->name << "} Sending user info." << endl;
#endif // GULTRA_DEBUG
					
					// User is already accepted, so register it normally.
					user_init_t uinit;
					strcpy(uinit.name, org->logged_user.name.c_str());
					strcpy(uinit.key,  org->logged_user.key.c_str());
					strcpy(uinit.iv,   org->logged_user.iv.c_str());
					org->client_send(client->mirror, PT_USER_INIT_RESPONSE, &uinit, sizeof(uinit));
			
					client->logged_user.name = std::string(uip->data.name);
					client->logged_user.key  = std::string(uip->data.key);
					client->logged_user.iv   = std::string(uip->data.iv);
					client->logged           = true;
					
					cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' accepted." << endl;
				}
				
				else 
				{
					cout << "[Server]{" << client->name << "} Do you accept user '" << uip->data.name << "' ? (Y/N)" << endl;
				
					// If this server is logged in, we will ask for the user if we should accept this userinit command.
					std::string lastcmd;
					console_reset_lastcommand();
					console_waitfor_command();
					lastcmd = console_get_lastcommand();
				
					if(lastcmd == "Y")
					{
						// If we accept the user, we save it to database.
#ifndef GULTRA_DEBUG
						cout << "[Server]{" << client->name << "} Sending user info." << endl;
#endif // GULTRA_DEBUG

						user_init_t uinit;
						strcpy(uinit.name, org->logged_user.name.c_str());
						strcpy(uinit.key,  org->logged_user.key.c_str());
						strcpy(uinit.iv,   org->logged_user.iv.c_str());
						org->client_send(client->mirror, PT_USER_INIT_RESPONSE, &uinit, sizeof(uinit));
			
						client->logged_user.name = std::string(uip->data.name);
						client->logged_user.key  = std::string(uip->data.key);
						client->logged_user.iv   = std::string(uip->data.iv);
						client->logged           = true;
					
						cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' accepted." << endl;
					}
					else
					{
						// User didn't accept the connection, just discard it.
						org->client_send(client->mirror, PT_USER_INIT_NOTACCEPTED, nullptr, 0);
						cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' not accepted." << endl;
					}
				}
			}
			
			else
			{
				// If this server is not logged in, we should send the client a packet to 
				// end the user initialization.
				org->client_send(client->mirror, PT_USER_INIT_NOTLOGGED, nullptr, 0);
				
				cout << "[Server]{" << client->name << "} User '" << uip->data.name << "' tried to logged in to you but"
				     << " you are not logged in. Please log in." << endl;
			}
			
			delete pclient;
	    }
	    
	    else if(pclient->m_type == PT_USER_INIT_RESPONSE)
		{
			cout << "[Server]{" << client->name << "} Initializing user." << endl;
			UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(pclient);
			cout << "[Server]{" << client->name << "} Connected user '" << uip->data.name << "'." << endl;
			
			client->logged_user.name = std::string(uip->data.name);
			client->logged           = true;
			delete pclient;
		}
		
		else if(pclient->m_type == PT_USER_INIT_NOTLOGGED)
		{
			cout << "[Server]{" << client->name << "} Can't initialize to server : It is not logged "
			     << "in." << endl;
			delete pclient;
		}
		
		else if(pclient->m_type == PT_USER_INIT_NOTACCEPTED)
		{
			cout << "[Server]{" << client->name << "} Client didn't accept you ! I can't do anythig for you..." << endl;
			delete pclient;
		}

        else if(pclient->m_type == PT_CLIENT_SENDFILE_INFO)
        {
            ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(pclient);
            if(!csfip)
            {
                cout << "[Server]{" << client->name << "} Error receiving File Info. " << endl;
                delete pclient;
                continue;
            }

            std::string fname(csfip->info.name);                   // File name
            uint32_t    flen   = csfip->info.lenght.data;          // File Lenght
            uint32_t    clen   = csfip->info.chunk_lenght.data;    // Lenght of one chunk
            uint32_t    clsz   = csfip->info.chunk_lastsize.data;  // Lenght of the last chunk
            uint32_t    cnum   = csfip->info.chunk_count.data;     // Number of chunks
            bool        chunks = csfip->info.has_chunk;            // True if we have more than one chunk.


            cout << "[Server]{" << client->name << "} Receiving file." << endl;
            cout << "[Server]{" << client->name << "} File Name -> '" << fname << "'." << endl;
            cout << "[Server]{" << client->name << "} File Size -> "  << flen  << "."  << endl;
#ifdef GULTRA_DEBUG
            if(chunks) {
                cout << "[Server]{" << client->name << "} Chunk Len  -> " << clen << "." << endl;
                cout << "[Server]{" << client->name << "} Chunk Last -> " << clsz << "." << endl;
                cout << "[Server]{" << client->name << "} Chunk num  -> " << cnum << "." << endl;
            }
#endif // GULTRA_DEBUG

            // We delete the info packet as we don't need it.
            delete pclient;
            pclient = nullptr;
            csfip   = nullptr;

            // We open a file for writing
            std::ofstream ofs(fname, std::ofstream::binary);
            if(!ofs)
            {
                // We can't open the file so abort the operation
                cout << "[Server]{" << client->name << "} Can't open file." << endl;

                // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                // because this server can't continue it.
                server_abort_operation(org, client);

                goto clientloop_continue;
            }

            if(chunks)
            {
                // We have cnum chunks to receive.

#ifdef GULTRA_DEBUG
                cout << "[Server]{" << client->name << "} Receiving File chunks." << endl;
#endif // GULTRA_DEBUG

                uint32_t sz          = 0;        // Current bytes received (for bytes received callback)
                uint32_t chunk_num   = 0;        // Current chunk number.
                uint32_t last_chunk  = cnum - 1; // Last chunk number.
                bool     mstop       = false;    // Do we have to break the loop ?
                while(!mstop)
                {
                    // We receive thhe chunk packet
                    Packet* vchunk = server_receive_packet(org, client);
                    if(!vchunk)
                    {
                        // We can't receive the chunk, so close the stream and abort the operation.
                        cout << "[Server]{" << client->name << "} Can't receive correct chunk." << endl;
                        ofs.close();

                        // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                        // because this server can't continue it.
                        server_abort_operation(org, client);

                        goto clientloop_continue;
                    }

                    // Reinterpret the chunk
                    ClientSendFileChunkPacket* chunk = reinterpret_cast<ClientSendFileChunkPacket*>(vchunk);
                    if(!chunk)
                    {
                        // We can't reinterpret the vchunk.
                        cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << endl;
                        delete vchunk;
                        ofs.close();

                        // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                        // because this server can't continue it.
                        server_abort_operation(org, client);

                        goto clientloop_continue;
                    }

                    // Write last chunk
                    if(chunk_num == last_chunk)
                    {
                        ofs.write(chunk->chunk, clsz);
                        sz   += clsz;
                        mstop = true;

#ifdef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Written chunk n��" << chunk_num << " -> " << clsz << " bytes." << endl;
#endif // GULTRA_DEBUG

                    }

                    // Write normal chunk
                    else
                    {
                        ofs.write(chunk->chunk, clen);
                        sz += clen;

#ifdef GULTRA_DEBUG
                        cout << "[Server]{" << client->name << "} Written chunk n��" << chunk_num << " -> " << clen << " bytes." << endl;
#endif // GULTRA_DEBUG

                    }

                    // Call callback
                    if(org->br_callback)
                        org->br_callback(fname, sz, flen);

                    // Destroy the chunk and iterate to next one.
                    delete chunk;
                    chunk_num++;
                }

                // Client may send PT_CLIENT_SENDFILE_TERMINATE packet but ignore it.
                // Close the stream.
                ofs.close();
                goto clientloop_continue;
            }

            // We only have one chunk to proceed.
            else
            {
                // Receive the chunk packet
                Packet* vchunk = server_receive_packet(org, client);
                if(!vchunk)
                {
                    // We can't receive the chunk, so close the stream and abort the operation.
                    cout << "[Server]{" << client->name << "} Can't receive correct chunk." << endl;
                    ofs.close();

                    // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                    // because this server can't continue it.
                    server_abort_operation(org, client);

                    goto clientloop_continue;
                }

                // Reinterpret the chunk
                ClientSendFileChunkPacket* chunk = reinterpret_cast<ClientSendFileChunkPacket*>(vchunk);
                if(!chunk)
                {
                    // We can't reinterpret the vchunk.
                    cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << endl;
                    delete vchunk;
                    ofs.close();

                    // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                    // because this server can't continue it.
                    server_abort_operation(org, client);

                    goto clientloop_continue;
                }

                // Here we write the entire file lenght.
                ofs.write(chunk->chunk, flen);

#ifdef GULTRA_DEBUG
                cout << "[Server] Written chunk -> " << flen << " bytes." << endl;
#endif // GULTRA_DEBUG

                if(org->br_callback)
                    org->br_callback(fname, flen, flen);

                // Delete chunk and close the stream.
                delete chunk;
                ofs.close();

                goto clientloop_continue;
            }
        }

// This section is made to make the continue goto must useful.
clientloop_continue:
        ;

    }

    return NULL;
}

client_t* server_create_client_thread_loop(server_t* server, client_t* client)
{
    pthread_t thread_client;
    pthread_create(&thread_client, 0, server_client_thread_loop, (void*) client);

    gthread_mutex_lock(&server->mutex);
    client->server_thread = thread_client;
    gthread_mutex_unlock(&server->mutex);

    return client;
}

client_t* server_create_client_thread_loop(server_t* server, int i)
{
    return server_create_client_thread_loop(server, &(server->clients.at(i)));
}

void* server_thread_loop(void* __serv)
{
    server_t* server = (server_t*) __serv;

    while(1)
    {
        /* A new client come. */
        SOCKADDR_IN csin;
        size_t sin_size = sizeof(csin);
        int csock = accept(server->sock, (SOCKADDR*) &csin, (socklen_t*) &sin_size);

        if(csock == SOCKET_ERROR)
        {
            std::cerr << "[Server] Can't accept client !" << endl;
            return (void*) errno;
        }

        cout << "[Server] Receiving new Client connection." << endl;
        Packet* pclient = receive_client_packet(csock);
        if(!pclient)
        {
            std::cerr << "[Server] Client disconnected before establishing connection." << endl;
            continue;
        }
        else
        {

            if(pclient->m_type == PT_CLIENT_INFO)
            {
#ifdef GULTRA_DEBUG
                cout << "[Server] Getting infos from new client." << endl;
#endif // GULTRA_DEBUG

                ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(pclient);

#ifdef GULTRA_DEBUG
                cout << "[Server] ID     = '" << cip->info.id.data     << "'." << endl;
                cout << "[Server] IDret  = '" << cip->info.idret.data  << "'." << endl;
                cout << "[Server] Name   = '" << cip->info.name        << "'." << endl;
                cout << "[Server] S Port = '" << cip->info.s_port.data << "'." << endl;
#endif // GULTRA_DEBUG

                // If client send PT_CLIENT_INFO, this is a demand to create in our server a new client_t structure.   (idret == ID_CLIENT_INVALID)
                //                           OR   this is a demand to complete an already existant client_t structure. (idret != ID_CLIENT_INVALID)

                if(cip->info.idret.data == ID_CLIENT_INVALID)
                {
                    client_t new_client;
                    new_client.id      = cip->info.id;
                    new_client.name.append(cip->info.name);
                    new_client.sock    = csock;
                    new_client.address = csin;
                    new_client.server  = (void*) server;
                    buffer_copy(new_client.pubkey, cip->info.pubkey);

                    // We create also the mirror connection
                    new_client.mirror         = new client_t;
                    new_client.mirror->id     = server_generate_new_id(server);
                    new_client.mirror->name   = server->name;
                    new_client.mirror->server = (void*) server;
                    new_client.mirror->mirror = nullptr;

                    // We create the connection
                    if(client_create(new_client.mirror, inet_ntoa(csin.sin_addr), cip->info.s_port.data) != GERROR_NONE)
                    {
                        cout << "[Server] Can't mirror connection to client '" << cip->info.name << "'." << endl;
                        delete new_client.mirror;
                        continue;
                    }

                    // We confirm the client-server that everything is alright
                    client_info_t info;
                    info.id.data     = new_client.mirror->id.data;
                    info.s_port.data = server->port;
                    info.idret.data  = new_client.id.data;
                    strcpy(info.name, new_client.mirror->name.c_str());
                    buffer_copy(info.pubkey, *(server->pubkey));

                    client_info_t serialized = serialize<client_info_t>(info);
                    if(client_send_packet(new_client.mirror, PT_CLIENT_INFO, &serialized, sizeof(serialized)) != GERROR_NONE)
                    {
                        cout << "[Server] Can't send packet 'PT_CLIENT_INFO' to client '" << new_client.name << "'." << endl;

                        // We so close the connection
                        client_close(new_client.mirror, true);
                        delete new_client.mirror;
                        continue;
                    }

                    gthread_mutex_lock(&server->mutex);
                    {
                        // Registering in the server
                        server->clients.push_back(new_client);
                        server->client_by_id[new_client.mirror->id.data] = & (server->clients.at(server->clients.size() - 1));
                    }
                    gthread_mutex_unlock(&server->mutex);

                    client_t* cclient = server->client_by_id[new_client.mirror->id.data];
                    cclient->established = true;

                    // We now send the PT_CONNECTION_ESTABLISHED packet and create the client thread.
                    server_create_client_thread_loop(server, cclient);
                    server->client_send(cclient->mirror, PT_CLIENT_ESTABLISHED, NULL, 0);

                    // If everything is alright, we can tell user
                    cout << "[Server] New Client connected (name = '" << cclient->name << "', id = '" << cclient->mirror->id.data << "')." << endl;
                    
                    // As client is valid, we can save it to the database.
                    if(user_database_isloaded())
					{
						dbclient_t dbc;
						dbc.ip   = std::string(inet_ntoa(csin.sin_addr));
						dbc.port = std::to_string(cip->info.s_port.data);
						udatabase->clients.push_back(dbc);
					}
                }

                else
                {
                    // We retrieve the client
                    client_t* new_client = server->client_by_id[cip->info.idret.data];
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
                continue;
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
                continue;
            }
        }
    }

    return 0;
}

client_t* server_find_client_by_name(server_t* server, const std::string& name)
{
    gthread_mutex_lock(&server->mutex);
    for(unsigned int i = 0; i < server->clients.size(); ++i)
    {
        if(server->clients[i].name == name)
        {
            pthread_mutex_unlock(&server->mutex);
            return &(server->clients[i]);
        }
    }
    gthread_mutex_unlock(&server->mutex);
    return NULL;
}

gerror_t server_abort_operation(server_t* server, client_t* client)
{
    // NOT IMPLEMENTED FOR NOW
    return GERROR_NONE;
}

/** @brief Create a new client connection.
 *
 *  @param server : A pointer to the server structure.
 *  @param out    : [out] A reference to a null client pointer. @note This
 *  pointer must be null as this functionn allocate the client and return in
 *  this variable the adress of the new client. The client is allocateed and destroyed
 *  by the server.
 *  @param adress : The adress to look at.
 *  @param port   : The port to create the connection to.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null or if out is different from null.
**/
gerror_t server_init_client_connection(server_t* server, client_t*& out, const char* adress, size_t port)
{
    if(!server || out != nullptr)
        return GERROR_BADARGS;

    // First we create the mirror. It will handle the socket to the client.
    client_t* mirror = new client_t;
    mirror->name     = server->name;
    mirror->id       = server_generate_new_id(server);
    mirror->mirror   = nullptr;
    mirror->server   = (void*) server;

    if(client_create(mirror, adress, port) != GERROR_NONE)
    {
        cout << "[Server] Can't create client connection for adress '" << adress << ":" << (uint32_t) port << "'." << endl;

        delete mirror;
        return GERROR_INVALID_CONNECT;
    }

#ifdef GULTRA_DEBUG
    cout << "[Server] Creating org client." << endl;
#endif // GULTRA_DEBUG

    // Once the mirror is created, we create the original client
    client_t new_client;
    new_client.id.data     = 0;
    new_client.mirror      = mirror;
    new_client.server      = server;
    new_client.sock        = SOCKET_ERROR;
    new_client.established = false;
    new_client.logged      = false;

#ifdef GULTRA_DEBUG
    cout << "[Server] Registering org client." << endl;
#endif // GULTRA_DEBUG

    gthread_mutex_lock(&server->mutex);
    {
        // We register the client to the server
        server->clients.push_back(new_client);
        server->client_by_id[new_client.mirror->id.data] = & (server->clients.at(server->clients.size() - 1));
    }
    gthread_mutex_unlock(&server->mutex);

#ifdef GULTRA_DEBUG
    cout << "[Server] Sending client info." << endl;
#endif // GULTRA_DEBUG

    // On connection, server expects info of this client to be send.
    client_info_t info;
    info.id.data     = mirror->id.data;
    info.idret.data  = ID_CLIENT_INVALID;
    info.s_port.data = server->port;
    strcpy(info.name, mirror->name.c_str());
    buffer_copy(info.pubkey, *(server->pubkey));

    client_info_t serialized = serialize<client_info_t>(info);
    client_send_packet(mirror, PT_CLIENT_INFO, &serialized, sizeof(client_info_t));

    // Now the destination should receive the PT_CLIENT_INFO packet, and send us
    // PT_CLIENT_INFO        to complete the client_t structure
    // PT_CLIENT_ESTABLISHED to be sure that everythig went fine
    // NOTE : Once PT_CLIENT_INFO packet is sent, we only use server->client_send to send
    // packet to the client.

#ifdef GULTRA_DEBUG
    cout << "[Server] Client inited." << endl;
#endif // GULTRA_DEBUG

    out = server->client_by_id[mirror->id.data];
    return GERROR_NONE;
}

void server_end_client(server_t* server, const std::string& client_name)
{
    if(server && !client_name.empty())
    {
        client_t* client = server_find_client_by_name(server, client_name);
        if(client)
        {
            gthread_mutex_lock(&server->mutex);

            uint32_t id = ID_CLIENT_INVALID;

            pthread_cancel(client->server_thread);
            if(client->sock != 0)
            {
                if(client->mirror != NULL)
                {
                    client_close(client->mirror);
                    id = client->mirror->id.data;
                    delete client->mirror;
                    client->mirror = 0;
                }

                closesocket(client->sock);
            }
            
            if(client->logged)
			{
				// We try to save the user if it has not already been saved.
				if(!user_is_loaded(client->logged_user.name))
				{
					udatabase->users[client->logged_user.name].name = client->logged_user.name;
					udatabase->users[client->logged_user.name].key  = client->logged_user.key;
					udatabase->users[client->logged_user.name].iv   = client->logged_user.iv;
				}
			}

            server->clients.erase(server->clients.begin() + server_find_client_index_private_(server, client_name));
            server->client_by_id[id] = nullptr;
            gthread_mutex_unlock(&server->mutex);
        }
    }
}

/** @brief Initialize a new connection with a logged in server.
 *
 *  @param server : The server object to use.
 *  @param out    : The connected user informations.
 *  @param adress : The adress of the client to connect.
 *  @param port   : The port of the client.
 *
 *  This function consist on several requests from this server to another
 *  one, aquiring some informations like currently logged user, server info, 
 *  and some more.
 *  When you use thhis function, it assumes that you automaticly trust
 *  the client to be a good client. It has to be the client wich should accept
 *  or deny you the first time you connect to him. 
 *
 *  @return
 *  - GERROR_NONE            : All is okay.
 *  - GERROR_BADARGS         : Bad args given.
 *  - GERROR_INVALID_CONNECT : Can't connect to server.
**/
gerror_t server_init_user_connection(server_t* server, user_t& out, const char* adress, size_t port)
{
	if(!server || !adress || port == 0)
		return GERROR_BADARGS;
		
	client_t* new_client = nullptr;
	server_init_client_connection(server, new_client, adress, port);
	if(!new_client)
		return GERROR_INVALID_CONNECT;

	if(server_wait_establisedclient(new_client, 4) != GERROR_NONE)
	{
		cout << "[Server] Can't establish client '" << adress << ":" << port << "'. (Timed out)" << endl;
		return GERROR_INVALID_CONNECT;
	}
	
	// Now client connection is established, we send a packet to init user connection
	user_init_t uinit;
	strcpy(uinit.name, server->logged_user.name.c_str());
	strcpy(uinit.key,  server->logged_user.key.c_str());
	strcpy(uinit.iv,   server->logged_user.iv.c_str());
	
	server->client_send(new_client->mirror, PT_USER_INIT, &uinit, sizeof(uinit));
	
	// Wait for the client to be logged in
	while(new_client->logged == false);
	
	out.name = new_client->logged_user.name;
	return GERROR_NONE;
}

/** @brief Wait for given client to be established.
 *  
 *  Use this function to wait for a client between the 'Connecting' state
 *  and the 'Connected' state.
 *
 *  @note You should always use a timeout because this is a blocking
 *  function and you may get stuck.
 *
 *  @param client  : Pointer to the client to wait for.
 *  @param timeout : Maximum time to wait for the client, in seconds.
 *
 *  @return
 *  - GERROR_NONE     : All is okay.
 *  - GERROR_TIMEDOUT : Time out has expired.
**/
gerror_t server_wait_establisedclient(client_t* client, uint32_t timeout)
{
	if(timeout > 0)
	{
		uint32_t startTime = time(NULL);
		uint32_t elapsedTime;
		while(client->established == false)
		{
			elapsedTime = difftime(time(NULL), startTime);
			if(elapsedTime > timeout)
				return GERROR_TIMEDOUT;
		}
		
		return GERROR_NONE;
	}
	else
	{
		while(client->established == false);
		return GERROR_NONE;
	}
}

GEND_DECL

