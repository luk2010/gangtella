/*
    This file is part of the GangTella project.
*/

#include "prerequesites.h"
#include "server.h"
#include "packet.h"

GBEGIN_DECL

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

gerror_t server_create(server_t* server)
{
    if(!server)
        return GERROR_BADARGS;

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Creating server at adress : '" << (uint32_t) server << "'." << std::endl;
#endif // GULTRA_DEBUG

    server->mutex   = PTHREAD_MUTEX_INITIALIZER;
    server->started = false;
    return GERROR_NONE;
}

int server_initialize(server_t* server, size_t port, int maxclients)
{
    if(!server)
        return GERROR_BADARGS;

    if(maxclients == 0)
    {
        std::cout << "[Server] Why initializing a server with 0 maximum clients ?!" << std::endl;
        return GERROR_BADARGS;
    }

#ifdef _WIN32

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Starting WSA2.0." << std::endl;
#endif // GULTRA_DEBUG

    int err;
    WSAData wsadata;
    err = WSAStartup(MAKEWORD(2, 0), &wsadata);
    if(err == WSASYSNOTREADY)
    {
        std::cout << "[Server] Could not start Windows Socket : "
                  << "The underlying network subsystem is not ready for network communication." << std::endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAVERNOTSUPPORTED)
    {
        std::cout << "[Server] Could not start Windows Socket : "
                  << "The version of Windows Sockets support requested is not provided by this particular Windows Sockets implementation." << std::endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEINPROGRESS)
    {
        std::cout << "[Server] Could not start Windows Socket : "
                  << "A blocking Windows Sockets 1.1 operation is in progress." << std::endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEPROCLIM)
    {
        std::cout << "[Server] Could not start Windows Socket : "
                  << "A limit on the number of tasks supported by the Windows Sockets implementation has been reached." << std::endl;
        return GERROR_WSASTARTUP;
    }
    else if(err == WSAEFAULT)
    {
        std::cout << "[Server] Could not start Windows Socket : "
                  << "The lpWSAData parameter is not a valid pointer." << std::endl;
        return GERROR_WSASTARTUP;
    }

#endif // _WIN32

    gthread_mutex_lock(&server->mutex);
    {

#ifdef GULTRA_DEBUG
        std::cout << "[Server] Initializing Server on port '" << port << "'." << std::endl;
#endif // GULTRA_DEBUG

        server->clients.reserve(maxclients);
        server->sock = socket(AF_INET, SOCK_STREAM, 0);

        if(server->sock == INVALID_SOCKET)
        {
            std::cerr << "[Server] Invalid server creation ! (Socket invalid)" << std::endl;
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_SOCKET;
        }

        SOCKADDR_IN sin = { 0 } ;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_family      = AF_INET;
        sin.sin_port        = htons(port);
        if(bind(server->sock, (SOCKADDR*) &sin, sizeof(sin) ) == SOCKET_ERROR)
        {
            std::cerr << "[Server] Invalid server creation ! (Can't bind socket on port : " << port << ".)" << std::endl;

            closesocket(server->sock);
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_BINDING;
        }

        if(listen(server->sock, maxclients) == SOCKET_ERROR)
        {
            std::cerr << "[Server] Invalid server creation ! (Can't listen to clients.)" << std::endl;

            closesocket(server->sock);
            gthread_mutex_unlock(&server->mutex);
            return GERROR_INVALID_LISTENING;
        }

        std::cout << "[Server] Ready to listen on port '" << port << "'.";
        server->started = true;
    }
    gthread_mutex_unlock(&server->mutex);

    return GERROR_NONE;
}

gerror_t server_launch(server_t* server)
{
    if(!server)
        return GERROR_BADARGS;

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Launching server thread." << std::endl;
#endif // GULTRA_DEBUG

    int ret = pthread_create(&server->thread, NULL, server_thread_loop, server);
    if(ret != 0)
        return GERROR_THREAD_CREATION;
    else
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

            pthread_cancel(client->server_thread);
            if(client->sock != 0)
            {
                if(client->mirror != NULL)
                {
                    client_close(client->mirror);
                    delete client->mirror;
                    client->mirror = 0;
                }

                closesocket(client->sock);
            }

            server->clients.erase(server->clients.begin() + server_find_client_index_private_(server, client_name));
            gthread_mutex_unlock(&server->mutex);
        }
    }
}

void* server_destroy(server_t* server)
{
    gthread_mutex_lock(&server->mutex);
    for(unsigned int i = 0; i < server->clients.size(); ++i)
    {
        pthread_cancel(server->clients[i].server_thread);
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
    std::cout << "[Server] Server destroyed." << std::endl;
    gthread_mutex_unlock(&server->mutex);

#ifdef _WIN32
    WSACleanup();
#endif // _WIN32

    return NULL;
}

void* server_client_thread_loop(void* data)
{
    client_t* client = (client_t*) data;

    while(1)
    {
        Packet* pclient = receive_client_packet(client->sock);
        if(!pclient)
        {
            std::cout << "[Server] Invalid packet reception." << std::endl;
            if(client->server)
                server_end_client((server_t*) client->server, client->name);
            else
                client_close(client);

            return NULL;
        }

        if(pclient->m_type == PT_CLIENT_CLOSING_CONNECTION)
        {
            std::cout << "[Server] Closing connection with client '" << client->name << "'." << std::endl;

            if(client->mirror != NULL)
            {
                client_close(client->mirror, false);
                delete client->mirror;
                client->mirror = 0;
            }

            closesocket(client->sock);
            client->sock = 0;

            // Erasing client from vector
            server_t* org = (server_t*) client->server;
            gthread_mutex_lock(&org->mutex);
            if(org != NULL)
            {
                for(unsigned int i = 0; i < org->clients.size(); ++i)
                {
                    if(org->clients[i].name == client->name)
                    {
                        org->clients.erase(org->clients.begin() + i);
                        break;
                    }
                }
            }
            gthread_mutex_unlock(&org->mutex);

            return NULL;
        }
        else if(pclient->m_type == PT_CLIENT_MESSAGE)
        {
            ClientMessagePacket* cmp = reinterpret_cast<ClientMessagePacket*>(pclient);
            std::string message = cmp->buffer;
            std::cout << "[Server]{" << client->name << "} " << message << std::endl;
        }
        else if(pclient->m_type == PT_CLIENT_ESTABLISHED)
        {
            std::cout << "[Server] Client " << client->name << " established connection." << std::endl;
        }


        else if(pclient->m_type == PT_CLIENT_SENDFILE_INFO)
        {
            std::cout << "[Server] Receiving file from client '" << client->name << "'." << std::endl;
            ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(pclient);
            std::cout << "[Server] File Name -> '" << csfip->info.name << "'." << std::endl;
            std::cout << "[Server] File Size -> " << csfip->info.lenght.data << "." << std::endl;

            std::ofstream ofs(csfip->info.name, std::ofstream::binary);

            if(csfip->info.has_chunk == true)
            {
                std::cout << "[Server] File Chunk count -> " << csfip->info.chunk_count.data << "." << std::endl;

                Packet* pchunkpacket = receive_client_packet(client->sock, csfip->info.chunk_lenght.data);
                if(!pchunkpacket)
                {
                    std::cout << "[Server] Can't receive client chunk." << std::endl;
                    ofs.close();
                    continue;
                }

                uint32_t chunk = 1;
                while(pchunkpacket && pchunkpacket->m_type == PT_CLIENT_SENDFILE_CHUNK)
                {
                    ClientSendFileChunkPacket* csfcp = reinterpret_cast<ClientSendFileChunkPacket*>(pchunkpacket);
                    if(chunk == csfip->info.chunk_count.data)
                    {
                        // Last chunk size
                        ofs.write(csfcp->chunk, csfip->info.chunk_lastsize.data);
                        std::cout << "[Server] Written chunk n°" << chunk - 1 << " -> " << csfip->info.chunk_lastsize.data << " bytes." << std::endl;
                    }
                    else
                    {
                        ofs.write(csfcp->chunk, csfip->info.chunk_lenght.data);
                        std::cout << "[Server] Written chunk n°" << chunk - 1 << " -> " << csfip->info.chunk_lenght.data << " bytes." << std::endl;
                    }

                    chunk++;
                    if(chunk == csfip->info.chunk_count.data)
                        pchunkpacket = receive_client_packet(client->sock, csfip->info.chunk_lastsize.data);
                    else
                        pchunkpacket = receive_client_packet(client->sock, csfip->info.chunk_lenght.data);
                }

                if(pchunkpacket && pchunkpacket->m_type != PT_CLIENT_SENDFILE_TERMINATE)
                    std::cout << "[Server] Bad end of connection ! Closing file." << std::endl;
                ofs.close();
            }
            else
            {
                Packet*                    pchunkpacket = receive_client_packet(client->sock);
                ClientSendFileChunkPacket* csfcp        = reinterpret_cast<ClientSendFileChunkPacket*>(pchunkpacket);

                ofs.write(csfcp->chunk, csfip->info.lenght.data);
                std::cout << "[Server] Written chunk -> " << csfip->info.lenght.data << " bytes." << std::endl;

                pchunkpacket = receive_client_packet(client->sock);
                if(pchunkpacket && pchunkpacket->m_type != PT_CLIENT_SENDFILE_TERMINATE)
                    std::cout << "[Server] Bad end of connection ! Closing file." << std::endl;
                ofs.close();
            }
        }
    }

    return NULL;
}

client_t* server_create_client_thread_loop(server_t* server, client_t* client)
{
    pthread_t thread_client;
    pthread_create(&thread_client, 0, server_client_thread_loop, (void*) client);

    gthread_mutex_lock(&server->mutex);
    client->server_thread = thread_client;

    if(client->mirror == NULL)
    {
        client_t* mclient = new client_t;
        mclient->name = client->name;
        client_create(mclient, inet_ntoa(client->address.sin_addr), CLIENT_PORT);
        client->mirror = mclient;
        client->mirror->server = server;
    }
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
        SOCKADDR_IN csin = { 0 };
        size_t sin_size = sizeof(csin);
        int csock = accept(server->sock, (SOCKADDR*) &csin, (unsigned int*) &sin_size);
        if(csock == SOCKET_ERROR)
        {
            std::cerr << "Can't accept client !" << std::endl;
            return (void*) errno;
        }

        std::cout << "[Server] Receiving new Client connection." << std::endl;
        Packet* pclient = receive_client_packet(csock);
        if(!pclient)
        {
            std::cerr << "Client disconnected before establishing connection." << std::endl;
            continue;
        }
        else
        {
            if(pclient->m_type != PT_CLIENT_NAME)
            {
                std::cerr << "Client didn't send correct packet !" << std::endl;
                delete pclient;
                continue;
            }
            else
            {
                std::cout << "[Server] Waiting Client information." << std::endl;
                ClientNamePacket* cnp = reinterpret_cast<ClientNamePacket*>(pclient);

                std::string cname = cnp->buffer;
                client_t* org = server_find_client_by_name(server, cname);
                if(org)
                {
                    gthread_mutex_lock(&server->mutex);
                    org->sock = csock;
                    org->address = csin;
                    gthread_mutex_unlock(&server->mutex);
                    std::cout << "[Server] Established new connection with client " << cname << ".";
                    server_create_client_thread_loop(server, org);
                    client_send_packet(org->mirror, PT_CLIENT_ESTABLISHED, NULL, 0);
                }
                else
                {
                    gthread_mutex_lock(&server->mutex);
                    client_t c;
                    c.sock    = csock;
                    c.name    = cnp->buffer;
                    c.address = csin;
                    c.mirror  = NULL;
                    c.server  = server;
                    server->clients.push_back(c);
                    gthread_mutex_unlock(&server->mutex);

                    std::cout << "[Server] Connected new client '" << c.name << "'." << std::endl;
                    server_create_client_thread_loop(server, server->clients.size()-1);
                }

                delete cnp;
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

client_t* server_init_client_connection(server_t* server, const std::string& cname, const char* adress, size_t port)
{
    if(server_find_client_by_name(server, cname) != NULL)
    {
        std::cout << "[Server] Can't init new connection because client " << cname << " already exists." << std::endl;
        return NULL;
    }

    client_t* mirror = new client_t;
    mirror->name = cname;
    mirror->mirror = 0;
    mirror->server = server;

    if(client_create(mirror, adress, port) == GERROR_NONE)
    {
        client_t org;
        org.mirror = mirror;
        org.name = cname;
        org.server = server;
        gthread_mutex_lock(&server->mutex);
        server->clients.push_back(org);
        gthread_mutex_unlock(&server->mutex);
        return mirror;
    }

    return NULL;
}

GEND_DECL

