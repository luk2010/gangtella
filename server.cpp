////////////////////////////////////////////////////////////
//
// GangTella - A multithreaded crypted server.
// Copyright (c) 2014 - 2015 Luk2010 (alain.ratatouille@gmail.com)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
////////////////////////////////////////////////////////////

#include "prerequesites.h"
#include "server.h"
#include "server_intern.h"
#include "packet.h"
#include "commands.h"
#include "serverlistener.h"

GBEGIN_DECL

#define server_access() gthread_mutex_lock(&server->mutex)
#define server_stopaccess() gthread_mutex_unlock(&server->mutex)

class InternalServerListener : public ServerListener
{
public:
    
    void onClientCreated(const ServerNewClientCreatedEvent* e)
    {
        Server* server = reinterpret_cast<Server*>(e->parent);
        // For now, the client is unlogged. So we can register
        // it to the unlogged clients vector.
        server_access();
        server->_unlogged_clients.push_back(e->client);
        server_stopaccess();
    }
    
    void onClientCompleted(const ServerClientCompletedEvent* e)
    {
        Server* server = reinterpret_cast<Server*>(e->parent);
        // For now, the client is unlogged. So we can register
        // it to the unlogged clients vector.
        server_access();
        server->_unlogged_clients.push_back(e->client);
        server_stopaccess();
    }
    
};

InternalServerListener* _listener = nullptr;
server_t server;

void* server_thread_loop (void*);

////////////////////////////////////////////////////////////
/** @brief Initialize the default parameters of the server_t structure.
 *
 *  It realize the different task :
 *  - initialize every field of the server (except the args field). 
 *  - try to create an RSA key if args.withssl is true.
 *  - try to load a default database (users.gtl) and creates a blank one
 *  if none found.
 *
 *  @return
 *  - GERROR_NONE on success.
**/
////////////////////////////////////////////////////////////
gerror_t server_create()
{

#ifdef GULTRA_DEBUG
    cout << "[Server] Name = '" << server.args.name << "'." << endl;
#endif // GULTRA_DEBUG

    server.mutex           = PTHREAD_MUTEX_INITIALIZER;
    server.started         = false;
    server.name            = server.args.name;
    server.crypt           = nullptr;
    server.status          = SS_NOTCREATED;
    
/* [DEPRECATED]
    server.logged_user     = nullptr;
    server.logged          = false;
    server.attachednetwork = nullptr;
*/
    
    // We set it to normal for now.
    // It is the user who set it manually to crypted.
    server_setsendpolicy(&server, SP_NORMAL);
    
    gthread_mutex_lock(&server.mutex);
    {
        // If we have ssl allowed, we creates the RSA key.
        if(server.args.withssl)
        {
#ifdef GULTRA_DEBUG
            cout << "[Server] Creating RSA encryption key." << endl;
#endif // GULTRA_DEBUG
            
            gerror_t err = Encryption::encryption_create(server.crypt);
            
            if(err != GERROR_NONE) {
                cout << "[Server] encryption_create return '" << gerror_to_string(err) << "'." << endl;
                exit(GERROR_ENCRYPT_GENERATE);
            }
            
            server.pubkey       = new buffer_t;
            server.pubkey->size = 0;
            if( (err = Encryption::encryption_get_publickey(server.crypt, server.pubkey)) != GERROR_NONE)
            {
                cout << "[Server] Public Key Error : '" << gerror_to_string(err) << "'." << endl;
                exit(GERROR_ENCRYPT_PUBKEY);
            }
            
            cout << "[Server] Key lenght = " << server.pubkey->size << "." << endl;
#ifdef GULTRA_DEBUG
            cout << "[Server] Public key = '" << std::string(reinterpret_cast<char*>(server.pubkey->buf), server.pubkey->size) << "'." << endl;
#endif // GULTRA_DEBUG
        }

/* [DEPRECATED]
        cout << "[Server] Setting up database." << endl;
        
        std::ifstream indb("users.gtl");
        if(!indb)
        {
            cout << "[Server] Can't find defaut database (users.gtl). Creating new." << endl;
            cout << "[Server] Name is 'default' but you can change it with 'db setname'." << endl;
            
            udatabase = new user_db_t;
            udatabase->autosave = true;
            udatabase->dbfile   = "users.gtl";
            udatabase->dbname   = "default";
        }
        else
        {
            indb.close();// We close the file stream to let user_database_load() open it.
            gerror_t err = user_database_load("users.gtl");
            if(err != GERROR_NONE)
            {
                cout << "[Server] Could not load database 'users.gtl'." << endl;
                exit(GERROR_USR_NODB);
            }
        }
*/
        
        cout << "[Server] Correctly created." << endl;
        if(server.args.withssl) {
            cout << "[Server] RSA size = " << RSA_size(server.crypt->keypair) << endl;
        }
        
        server.status = SS_CREATED;
        _listener = new InternalServerListener;
        server.addListener(_listener);
    }
    gthread_mutex_unlock(&server.mutex);
    return GERROR_NONE;
}

////////////////////////////////////////////////////////////
/** @brief Initialize a new server structure.
 *  @note This function assumes server is not null, and mutex and started
 *  are already initialized.
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
////////////////////////////////////////////////////////////
gerror_t server_initialize()
{
    gthread_mutex_lock(&server.mutex);
    {
        if(server.args.maxclients == 0)
        {
            cout << "[Server] Max clients number invalid (0)." << endl;
            exit(GERROR_BADARGS);
        }
        
        if(server.args.port == 0)
        {
            cout << "[Server] Invalid port (0)." << endl;
            exit(GERROR_BADARGS);
        }
    }
    gthread_mutex_unlock(&server.mutex);

    gerror_t err = NetworkInit();
    if(err != GERROR_NONE){
        //exit(err);
    }

    gthread_mutex_lock(&server.mutex);
    {

#ifdef GULTRA_DEBUG
        cout << "[Server] Initializing Server on port '" << server.args.port << "'." << endl;
#endif // GULTRA_DEBUG

        server.clients.reserve(server.args.maxclients);
        server.sock = socket(AF_INET, SOCK_STREAM, 0);

        if(server.sock == INVALID_SOCKET)
        {
            std::cerr << "[Server] Invalid server creation ! (Socket invalid)" << endl;
            gthread_mutex_unlock(&server.mutex);
            return GERROR_INVALID_SOCKET;
        }

        SOCKADDR_IN sin;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(server.args.port);
        if(bind(server.sock, (SOCKADDR*) &sin, sizeof(sin) ) == SOCKET_ERROR)
        {
            cout << "[Server] Invalid server creation ! (Can't bind socket on port : " << server.args.port << ".)" << endl;

            closesocket(server.sock);
            gthread_mutex_unlock(&server.mutex);
            return GERROR_INVALID_BINDING;
        }

        if(listen(server.sock, server.args.maxclients) == SOCKET_ERROR)
        {
            std::cerr << "[Server] Invalid server creation ! (Can't listen to clients.)" << endl;

            closesocket(server.sock);
            gthread_mutex_unlock(&server.mutex);
            return GERROR_INVALID_LISTENING;
        }

        cout << "[Server] Ready to listen on port '" << server.args.port << "'." << endl;
        server.started = true;
        server.port    = (uint32_t) server.args.port;
        server.status  = SS_INITED;
    }
    gthread_mutex_unlock(&server.mutex);

    return GERROR_NONE;
}

////////////////////////////////////////////////////////////
/** @brief Launch the Server thread.
 *
 *  @param server : A pointer to the server structure.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *  - GERROR_THREAD_CREATION if thread cannot be created.
**/
////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////
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
////////////////////////////////////////////////////////////
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

    cout << "[Server] Server destroyed." << endl;
    
    if(_listener)
        delete _listener;

    if(!gthread_mutex_unlock(&server->mutex))
        return GERROR_MUTEX_UNLOCK;

    return err;
}

////////////////////////////////////////////////////////////
/** @brief Set the new SendPolicy of the given server.
 *
 *  @param server : The server to change the send policy.
 *  @param policy : The new policy to adopt. This policy
 *  can be \c SP_NORMAL or \c SP_CRYPTED. We hightly 
 *  recommend the use of \c SP_NORMAL. 
 *
 *  @note
 *  Changing this value when the server already has clients
 *  connected has undefined behaviour.
 *
 *  @return 
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null, or if the policy is
 *    invalid.
**/
////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////
/** @brief Set the callback when the server receives bytes, 
 *  generally used when receiving a file.
 *
 *  @param server : The server to change the callback. 
 *  @param callback : The callback to use.
 *
 *  You can use the callback to provide custom handling of the
 *  received amount of data when receiving files, like drawing
 *  a waiting bar.
 *
 *  @return 
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *
**/
////////////////////////////////////////////////////////////
gerror_t server_setbytesreceivedcallback(server_t* server, bytesreceived_t callback)
{
    if(!server)
        return GERROR_BADARGS;
    server->br_callback = callback;
    return GERROR_NONE;
}

////////////////////////////////////////////////////////////
/** @brief Set the callback when the server send bytes,
 *  generally used when sending a file.
 *
 *  @param server : The server to change the callback.
 *  @param callback : The callback to use.
 *
 *  You can use the callback to provide custom handling of the
 *  sent amount of data when sending files, like drawing
 *  a waiting bar.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null.
 *
 **/
////////////////////////////////////////////////////////////
gerror_t server_setbytessendcallback(server_t* server, bytessend_t callback)
{
    if(!server)
        return GERROR_BADARGS;
    server->bs_callback = callback;
    return GERROR_NONE;
}

////////////////////////////////////////////////////////////
/** @brief Receive a packet from given client and decrypt it 
 *  if encrypted.
 *
 *  @note 
 *  This is a timed out version of server_wait_packet(). This 
 *  means that after a certain time, the function will return 
 *  as an error.
 *
 *  @param server : Pointer to the server_t object.
 *  @param client : Pointer to the client_t object.
 *
 *  @return
 *  - nullptr if packet can't be received or if packet can't 
 *  be decrypted.
 *  - A Packet object that correspond to what the client send.
 *  @note You must delete this object yourself.
**/
////////////////////////////////////////////////////////////
PacketPtr server_receive_packet(server_t* server, client_t* client)
{
    Packet* pclient = receive_client_packet(client->sock);
    if(!pclient)
    {
        cout << "[Server] Invalid packet reception." << endl;
/*
        if(server)
            server_end_client(server, client->name);
        else
            client_close(client);
*/
        return nullptr;
    }
    
    server_preinterpret_packet(server, client, pclient);
    return pclient;
}

////////////////////////////////////////////////////////////
/** @brief Wait for a packet to be received by the server.
 *
 *  @param server : The server to wait.
 *  @param client : The client to wait.
 *
 *  @note 
 *  This is a non-timed out functions, blocking the thread.
 *  If connection cannot be checked, it automaticly returns
 *  a null packet.
 *
 *  @return
 *  - nullptr if packet can't be received or if packet can't
 *  be decrypted.
 *  - A Packet object that correspond to what the client send.
 *  @note You must delete this object yourself.
 *
**/
////////////////////////////////////////////////////////////
PacketPtr server_wait_packet(server_t* server, client_t* client)
{
    PacketPtr pclient = nullptr;
    
    // We wait for a packet to come.
    gerror_t err = packet_wait(client->sock, client->mirror->sock, pclient);
    
    if(err != GERROR_NONE)
    {
        cout << "[Server] Can't wait for packet : " << gerror_to_string(err) << endl;
        return nullptr;
    }
    
    // We then preinterpret the packet.
    server_preinterpret_packet(server, client, pclient);
    return pclient;
}

////////////////////////////////////////////////////////////
/** @brief Preinterpret given packet (decrypt it if possible).
 *
 *  @param server : The server to use.
 *  @param client : The client currently connected.
 *  @param pclient : A returned Packet, which can be null. 
 *
 *  @note
 *  On \c GULTRA_DEBUG mode, this function will produce many
 *  strings. It will describe the amount of data decrypted.
 *  This can be useful to show errors. 
 *
 *  @note
 *  This function can decrypt Packet in more than one block, 
 *  which suppose that the distant server can send parted
 *  crypted blocks.
**/
////////////////////////////////////////////////////////////
void server_preinterpret_packet(server_t* server, client_t* client, PacketPtr& pclient)
{
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
            size_t chunk_num    = eip->info.cryptedblock_number; // Number of chunk
            size_t chunk_lastsz = eip->info.cryptedblock_lastsz; // Size of the last chunk
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
                        
                        pclient = nullptr;
                        return;
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
                pclient = vret;
                return;
            }

            else
            {
                Packet* cpacket = packet_choose_policy(ptype);
                packet_interpret(ptype, cpacket, 0, 0);
                pclient = cpacket;
                return;

#ifdef GULTRA_DEBUG
                cout << "[Server]{" << client->name << "} Received Encrypted Packet." << endl;
#endif // GULTRA_DEBUG
            }
        }
        else
        {
            cout << "[Server]{" << client->name << "} Can't decrypt data without public key !" << endl;
            pclient = nullptr;
            return;
        }
    }
    
}

////////////////////////////////////////////////////////////
/** @brief Notifiates the given client that we want to unlog.
 *
 *  @param server : The server to use.
 *  @param client : The client to send.
 *
 *  @return
 *  - GERROR_NONE    : No errors occured.
 *  - GERROR_BADARGS : server or client is null.
**/
////////////////////////////////////////////////////////////
gerror_t server_end_user_connection(server_t* server, client_t* client)
{
	if(!server || !client)
		return GERROR_BADARGS;
		
	if(!globalsession.user)
	{
#ifdef GULTRA_DEBUG
		cout << "[Server] Can't end user connection while not logged in (logic --')." << endl;
#endif // GULTRA_DEBUG
		return GERROR_NONE;
	}
	
	server->client_send(client, PT_USER_END, NULL, 0);
	
	// Now client should send us packet PT_USER_END_RESPONSE and our local client
	// will unlog from him too.
	
	return GERROR_NONE;
}

////////////////////////////////////////////////////////////
/** @brief Unlog user from server and notifiate every clients.
 *  
 *  @return
 *  - GERROR_NONE    : No errors occured.
 *  - GERROR_BADARGS : server is null.
**/
////////////////////////////////////////////////////////////
gerror_t server_unlog(server_t* server)
{
	if(!server)
		return GERROR_BADARGS;
	
	if(!globalsession.user)
	{
#ifdef GULTRA_DEBUG
		cout << "[Server] Can't unlog while not logged in (logic --')." << endl;
#endif // GULTRA_DEBUG
		return GERROR_NONE;
	}
	
	for(unsigned int i = 0; i < server->clients.size(); ++i)
	{
		gerror_t err = server_end_user_connection(server, &(server->clients[i]));
		if(err != GERROR_NONE)
			cout << "[Server] Unlog error : (" << server->clients[i].name << ") " << gerror_to_string(err) << endl;
	}
	
	user_destroy(globalsession.user);
	//server->logged = false;
	cout << "[Server] Correctly unlogged." << endl;
	return GERROR_NONE;
}

client_t* server_create_client_thread_loop(server_t* server, int i)
{
    return server_create_client_thread_loop(server, &(server->clients.at(i)));
}

void* server_thread_loop(void* __serv)
{
    server_t* server   = (server_t*) __serv;
    server->status     = SS_STARTED;
    server->_must_stop = false;
    
    // We must create fake client to send ourselves some important packet.
    // This is a super mirror.
    
    // The localhost has always privilegied rights on commands. He can create a super-client
    // to communicate deeply with the program. This is used to make development of GUI applications
    // much more easy.
    
#ifdef GULTRA_DEBUG
    cout << "[Server] Creating localhost." << endl;
#endif
    /*
    client_t* localhostc = nullptr;
    server_init_client_connection(server, localhostc, "127.0.0.1", server->port);
    server->localhost = localhostc;
    */
    
    ServerStartedEvent* e = new ServerStartedEvent;
    e->type = "ServerStartedEvent";
    e->parent = server;
    server->sendEvent(e);
    delete e;

    while(!(server->_must_stop))
    {
        server_access();
        {
            server->status = SS_STARTED;
        }
        server_stopaccess();
        
        /* A new client come. */
        SOCKADDR_IN csin;
        size_t sin_size = sizeof(csin);
        int csock = accept(server->sock, (SOCKADDR*) &csin, (socklen_t*) &sin_size);

        if(csock == SOCKET_ERROR)
        {
            cout << "[Server] Can't accept client !" << endl;
            return (void*) (uintptr_t) errno;
        }
        
        /* Client acceptation
         When the server receives a new client connection, it launches
         a thread to treat the packet. This let us having multiple client 
         connecting at the same time to the server.
        */
        
        server_launch_accepting_thread(server, csock, csin);
    }
    
    server->status = SS_STOPPED;
    return (void*) GERROR_NONE;
}

gerror_t server_stop(server_t* server)
{
    if(!server)
        return GERROR_BADARGS;
    
    ServerWillStopEvent* e1 = new ServerWillStopEvent;
    e1->type = "ServerWillStopEvent";
    e1->parent = server;
    server->sendEvent(e1);
    delete e1;
    
    server->_must_stop = true;
    closesocket(server->sock);
    pthread_join(server->thread, nullptr);
    
    ServerStoppedEvent* e = new ServerStoppedEvent;
    e->type = "ServerStoppedEvent";
    e->parent = server;
    server->sendEvent(e);
    delete e;
    
    return GERROR_NONE;
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

gerror_t server_abort_operation(server_t* server, client_t* client, int error)
{
    // NOT IMPLEMENTED FOR NOW
    return GERROR_NOTIMPLEMENTED;
}

gerror_t server_notifiate(server_t* server, client_t* client, int error)
{
    return GERROR_NOTIMPLEMENTED;
}

/** @brief Create a new client connection.
 *
 *  If the given client connection parameters are already used, the already
 *  existing connection is returned.
 *
 *  @param server : A pointer to the server structure.
 *  @param out    : [out] A reference to a null client pointer. @note This
 *  pointer must be null as this functionn allocate the client and return in
 *  this variable the adress of the new client. The client is allocated and destroyed
 *  by the server.
 *  @param adress : The adress to look at.
 *  @param port   : The port to create the connection to.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if server is null or if out is different from null.
 *  - GERROR_ALLOC if an allocation problems occurs (for mirror or org client).
**/
gerror_t server_init_client_connection(server_t* server, client_t*& out, const char* adress, size_t port)
{
    if(!server || out != nullptr)
        return GERROR_BADARGS;
    
    server_wait_status(server, SS_STARTED);
        
	// We check if connection does not already exist
    out = server_client_exist(server, adress, port);
    if(out)
    {
        cout << "[Server] Client ('" << adress << ":" << port << "') already exist (" << out->name << ")." << endl;
        return GERROR_NONE;
    }
    
#ifdef GULTRA_DEBUG
    cout << "[Server] Creating mirror client." << endl;
#endif

    // First we create the mirror. It will handle the socket to the client.
    clientptr_t mirror = nullptr;
    if(client_alloc(&mirror, server_generate_new_id(server), nullptr, (void*) server) != GERROR_NONE)
    {
        cout << "[Server] Can't allocate mirror client ! Aborting creation." << endl;
        return GERROR_ALLOC;
    }
    
    // We set its name to our current server name.
    mirror->name     = server->name;

    // Create the connection.
    if(client_create(mirror, adress, port) != GERROR_NONE)
    {
        cout << "[Server] Can't create client connection for adress '" << adress << ":" << port << "'." << endl;

        client_free(&mirror);
        return GERROR_INVALID_CONNECT;
    }

#ifdef GULTRA_DEBUG
    cout << "[Server] Creating org client." << endl;
#endif // GULTRA_DEBUG

    // Once the mirror is created, we create the original client
    clientptr_t new_client = nullptr;
    if(client_alloc(&new_client, 0, mirror, (void*) server) != GERROR_NONE)
    {
        cout << "[Server] Can't allocate org client ! Aborting creation." << endl;
        
        client_close(mirror);
        client_free(&mirror);
        return GERROR_ALLOC;
    }

    new_client->sock        = SOCKET_ERROR;
    new_client->established = false;
    new_client->logged      = false;

#ifdef GULTRA_DEBUG
    cout << "[Server] Registering client." << endl;
#endif // GULTRA_DEBUG

    server_access();
    {
        // We register the client to the server
        server->clients.push_back(*new_client);
        server->client_by_id[new_client->mirror->id] = & (server->clients.at(server->clients.size() - 1));
    }
    server_stopaccess();

#ifdef GULTRA_DEBUG
    cout << "[Server] Sending client info." << endl;
#endif // GULTRA_DEBUG

    // On connection, server expects info of this client to be send.
    client_info_t info;
    info.id     = mirror->id;
    info.idret  = ID_CLIENT_INVALID;
    info.s_port = server->port;
    strcpy(info.name, mirror->name.c_str());
    buffer_copy(info.pubkey, *(server->pubkey));

    client_info_t serialized = serialize<client_info_t>(info);
    client_send_packet(new_client, PT_CLIENT_INFO, &serialized, sizeof(client_info_t));

    // Now the destination should receive the PT_CLIENT_INFO packet, and send us
    // PT_CLIENT_INFO        to complete the client_t structure
    // PT_CLIENT_ESTABLISHED to be sure that everythig went fine
    // NOTE : Once PT_CLIENT_INFO packet is sent, we only use server->client_send to send
    // packet to the client.

#ifdef GULTRA_DEBUG
    cout << "[Server] Client inited." << endl;
#endif // GULTRA_DEBUG

    out = server->client_by_id[new_client->mirror->id];
    return GERROR_NONE;
}

client_t* server_client_exist(server_t* server, const std::string& cip, const size_t& cport)
{
    for(unsigned int i = 0; i < server->clients.size(); ++i)
    {
        if(std::string(inet_ntoa(server->clients[i].address.sin_addr)) == cip &&
           cport == ntohs(server->clients[i].mirror->address.sin_port) )
        {
            return &(server->clients[i]);
        }
    }
    
    return nullptr;
}

void server_end_client(server_t* server, const std::string& client_name)
{
    if(server && !client_name.empty())
    {
        client_t* client = server_find_client_by_name(server, client_name);
        if(client)
        {
            // Launching an event to notifiate the near ending
            // of this client connection.
            ServerClientClosingEvent* e1 = new ServerClientClosingEvent;
            e1->type   = "ServerClientClosingEvent";
            e1->parent = server;
            e1->client = client;
            server->sendEvent(e1);
            delete e1;
            
            {
                gthread_mutex_lock(&server->mutex);
                uint32_t id = ID_CLIENT_INVALID;
                
                pthread_cancel(client->server_thread);
                if(client->sock != 0)
                {
                    if(client->mirror != NULL)
                    {
                        client_close(client->mirror);
                        id = client->mirror->id;
                        delete client->mirror;
                        client->mirror = 0;
                    }
                    
                    closesocket(client->sock);
                }
                
                if(client->logged)
                {
                    user_destroy(client->logged_user);
                    client->logged = false;
                }
                
                // Launch an event to notifiate Listeners that the Client has been
                // closed.
                ServerClientClosedEvent* e2 = new ServerClientClosedEvent;
                e2->type   = "ServerClientClosedEvent";
                e2->parent = server;
                e2->client = client;
                server->sendEvent(e2);
                delete e2;
                
                // Delete the client.
                server->clients.erase(server->clients.begin() + server_find_client_index_private_(server, client_name));
                server->client_by_id[id] = nullptr;
                gthread_mutex_unlock(&server->mutex);
            }
            
            
        }
    }
}

/** @brief Initialize a new connection with a logged in server.
 *
 *  @param server : The server object to use.
 *  @param out    : [deactivated] The connected user informations.
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
gerror_t server_init_user_connection(server_t* server, /* user_t& out, */ const char* adress, size_t port)
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
    
    client_thread_setstatus(new_client, CO_ESTABLISHING);
	
	// Now client connection is established, we send a packet to init user connection
	user_init_t uinit;
	strcpy(uinit.name, globalsession.user->m_name->buf);
	strcpy(uinit.key,  globalsession.user->m_key->buf);
	strcpy(uinit.iv,   globalsession.user->m_iv->buf);
	
	server->client_send(new_client, PT_USER_INIT, &uinit, sizeof(uinit));
	
	// Wait for the client to be logged in
	while(new_client->logged == false);
    
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
		time_t startTime = time(NULL);
		time_t elapsedTime;
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

/** @brief Check if a client program is valid. 
 *  
 *  @warning Not implemented for now. I don't know how to verify
 *  the program integrity.
**/
gerror_t server_check_client(server_t* server, client_t* client)
{
    return GERROR_NONE;
}

/** @brief Returns the server current status.
**/
int server_get_status(server_t* server)
{
    return (int) server->status;
}

/** @brief Wait for the server to have a given status, with a given timeout.
 *  @param server  : Pointer to the server.
 *  @param status  : Status to wait.
 *  @param timeout : Maximum time to wait. 0 is infinite.
**/
gerror_t server_wait_status(server_t* server, int status, long timeout)
{
    if(timeout > 0)
    {
        time_t startTime = time(NULL);
		time_t elapsedTime;
		while(server->status != status)
		{
			elapsedTime = difftime(time(NULL), startTime);
			if(elapsedTime > timeout)
				return GERROR_TIMEDOUT;
		}
		
		return GERROR_NONE;
    }
    else
    {
        while(server->status != status) ;
        return GERROR_NONE;
    }
}

GEND_DECL

