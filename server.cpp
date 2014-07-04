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

/** @brief Generate aa new id for given server. */
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
    std::cout << "[Server] Creating server at adress : '" << (uint32_t) server << "'." << std::endl;
    std::cout << "[Server] Name = '" << disp_name << "'." << std::endl;
#endif // GULTRA_DEBUG

    server->mutex   = PTHREAD_MUTEX_INITIALIZER;
    server->started = false;
    server->name    = disp_name;
    server->crypt   = nullptr;

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Creating RSA encryption key." << std::endl;
#endif // GULTRA_DEBUG

    gerror_t err = Encryption::encryption_create(server->crypt);

#ifdef GULTRA_DEBUG
    std::cout << "[Server] encryption_create return '" << gerror_to_string(err) << "'." << std::endl;
#endif // GULTRA_DEBUG

    server->pubkey       = new buffer_t;
    server->pubkey->size = 0;
    if( (err = Encryption::encryption_get_publickey(server->crypt, server->pubkey)) != GERROR_NONE)
    {
#ifdef GULTRA_DEBUG
        std::cout << "[Server] Public Key Error : '" << gerror_to_string(err) << "'." << std::endl;
#endif // GULTRA_DEBUG
        delete server->pubkey;
    }

    // We set it to normal for now.
    server_setsendpolicy(server, SP_NORMAL);

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Key lenght = " << server->pubkey->size << "." << std::endl;
    std::cout << "[Server] Public key = '" << std::string(reinterpret_cast<char*>(server->pubkey->buf), server->pubkey->size) << "'." << std::endl;
#endif // GULTRA_DEBUG

    std::cout << "[Server] Correctly created." << std::endl;
    std::cout << "[Server] RSA size = " << RSA_size(server->crypt->keypair) << std::endl;

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

        std::cout << "[Server] Ready to listen on port '" << port << "'." << std::endl;
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
    std::cout << "[Server] Launching server thread." << std::endl;
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
        std::cout << "[Server] Can't destroy null server." << std::endl;
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
    std::cout << "[Server] Cleaning Windows Socket 2.0." << std::endl;
#endif // GULTRA_DEBUG

    int ret = WSACleanup();

    if(ret == WSANOTINITIALISED)
    {
        std::cout << "[Server] Could not clean Windows Socket : "
                  << "A successful WSAStartup call must occur before using this function." << std::endl;
        err = GERROR_WSACLEANING;
    }
    else if(ret == WSAENETDOWN)
    {
        std::cout << "[Server] Could not clean Windows Socket : "
                  << "The network subsystem has failed." << std::endl;
        err = GERROR_WSACLEANING;
    }
    else if(ret == WSAEINPROGRESS)
    {
        std::cout << "[Server] Could not clean Windows Socket : "
                  << "A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function." << std::endl;
        err = GERROR_WSACLEANING;
    }

#endif // _WIN32

    std::cout << "[Server] Server destroyed." << std::endl;

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
        std::cout << "[Server] Invalid packet reception." << std::endl;
        if(client->server)
            server_end_client((server_t*) client->server, client->name);
        else
            client_close(client);

        return NULL;
    }

    if(pclient->m_type == PT_ENCRYPTED_INFO)
    {
        // We received encrypted data
#ifdef GULTRA_DEBUG
        std::cout << "[Server]{" << client->name << "} Receiving Encrypted data." << std::endl;
#endif // GULTRA_DEBUG

        // Verifying we have the public key
        if(client->pubkey.size > 0)
        {
            EncryptedInfoPacket* eip = reinterpret_cast<EncryptedInfoPacket*>(pclient);
            size_t chunk_size   = RSA_SIZE;
            size_t data_size    = chunk_size - 11;
            size_t chunk_num    = eip->info.cryptedblock_number.data;
            size_t chunk_lastsz = eip->info.cryptedblock_lastsz.data;
            buffer_t& pubkey    = client->pubkey;
            uint8_t ptype       = eip->info.ptype;

            // We have everything we need so destroy the EncryptedInfoPacket.
            delete eip;
            eip     = nullptr;
            pclient = nullptr;

            Packet* cpacket = packet_choose_policy(ptype);
            if(!cpacket)
            {
                std::cout << "[Server]{" << client->name << "} Can't choose good policy for Packet !" << std::endl;
                return nullptr;
            }

            // Checking chunk number
            if(chunk_num > 1)
            {
                // We have chunk_num chunks to fill
                size_t         total_size = data_size * (chunk_num - 1) + chunk_lastsz;
                unsigned char* recvdata   = nullptr;
                unsigned char* data       = reinterpret_cast<unsigned char*>(cpacket) + sizeof(Packet);
                unsigned char* current    = nullptr;
                Packet*        chunk      = nullptr;

                unsigned int i = 0;
                for(; i < chunk_num - 1; ++i)
                {
                    current = data + ( i * ( RSA_SIZE - 11 ) );
                    chunk   = receive_client_packet(client->sock);
                    if(chunk->m_type != PT_ENCRYPTED_CHUNK)
                    {
                        std::cout << "[Server]{" << client->name << "} Can't receive Encrypted chunk !" << std::endl;
                        delete chunk;
                        delete cpacket;
                        return nullptr;
                    }

#ifdef GULTRA_DEBUG
                    std::cout << "[Server]{" << client->name << "} Received chunk " << i << " encrypted !" << std::endl;
#endif // GULTRA_DEBUG

                    EncryptedChunkPacket* echunk = reinterpret_cast<EncryptedChunkPacket*>(chunk);
                    recvdata = echunk->chunk;
                    size_t len = (size_t) Encryption::decrypt(pubkey, current, recvdata, chunk_size);
                    if(len != data_size)
                    {
                        std::cout << "[Server]{" << client->name << "} Can't decrypt enough bytes ! (" << len << "\\" << data_size << ")" << std::endl;
                        delete chunk;
                        delete cpacket;
                        return nullptr;
                    }

                    delete chunk;
                }

                current = data + ( i * ( RSA_SIZE - 11 ) );
                chunk = receive_client_packet(client->sock);
                if(chunk->m_type != PT_ENCRYPTED_CHUNK)
                {
                    std::cout << "[Server]{" << client->name << "} Can't receive Encrypted chunk !" << std::endl;

                    delete chunk;
                    delete cpacket;
                    return nullptr;
                }

                EncryptedChunkPacket* echunk = reinterpret_cast<EncryptedChunkPacket*>(chunk);
                recvdata = echunk->chunk;
                Encryption::decrypt(pubkey, current, recvdata, chunk_lastsz);

                packet_interpret(ptype, cpacket, data, total_size);

#ifdef GULTRA_DEBUG
                std::cout << "[Server]{" << client->name << "} Received Encrypted Packet. Packet num = " << chunk_num << "." << std::endl;
                std::cout << "[Server]{" << client->name << "} Type = " << (int) ptype << ", size = " << total_size << "." << std::endl;
#endif // GULTRA_DEBUG

                delete chunk;
                return cpacket;
            }
            else if(chunk_num == 1)
            {
                size_t         total_size = chunk_lastsz;
                unsigned char* recvdata   = nullptr;
                unsigned char* data       = (unsigned char*) malloc(data_size);
                Packet*        chunk      = nullptr;

                chunk = receive_client_packet(client->sock);
                if(chunk && chunk->m_type != PT_ENCRYPTED_CHUNK)
                {
                    std::cout << "[Server]{" << client->name << "} Can't receive Encrypted chunk !" << std::endl;

                    delete chunk;
                    delete cpacket;
                    free(data);
                    return nullptr;
                }

                EncryptedChunkPacket* echunk = reinterpret_cast<EncryptedChunkPacket*>(chunk);
                recvdata = echunk->chunk;
                int sz =  Encryption::decrypt(pubkey, data, recvdata, chunk_size);

                packet_interpret(ptype, cpacket, data, total_size);

                delete chunk;
                free(data);

#ifdef GULTRA_DEBUG
                std::cout << "[Server]{" << client->name << "} Received Encrypted Packet." << std::endl;
                std::cout << "[Server]{" << client->name << "} Type = " << (int) ptype << ", size = " << sz << "." << std::endl;
#endif // GULTRA_DEBUG

                return cpacket;
            }
            else
            {
                packet_interpret(ptype, cpacket, 0, 0);
                return cpacket;

#ifdef GULTRA_DEBUG
                std::cout << "[Server]{" << client->name << "} Received Encrypted Packet." << std::endl;
#endif // GULTRA_DEBUG
            }
        }
        else
        {
            std::cout << "[Server]{" << client->name << "} Can't decrypt data without public key !" << std::endl;
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
        Packet* pclient = server_receive_packet(org, client);

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

            std::cout << "[Server]{" << client->name << "} Closed client." << std::endl;

            // Erasing client from vectors
            int cindex = server_find_client_index_private_(org, client->name);

            gthread_mutex_lock(&org->mutex);
            org->clients.erase(org->clients.begin() + cindex);
            if(cid != ID_CLIENT_INVALID)
                org->client_by_id[cid] = nullptr;
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
            std::cout << "[Server]{" << client->name << "} Established connection." << std::endl;
        }


        else if(pclient->m_type == PT_CLIENT_SENDFILE_INFO)
        {
            ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(pclient);
            if(!csfip)
            {
                std::cout << "[Server]{" << client->name << "} Error receiving File Info. " << std::endl;
                delete pclient;
                continue;
            }

            std::string fname(csfip->info.name);                   // File name
            uint32_t    flen   = csfip->info.lenght.data;          // File Lenght
            uint32_t    clen   = csfip->info.chunk_lenght.data;    // Lenght of one chunk
            uint32_t    clsz   = csfip->info.chunk_lastsize.data;  // Lenght of the last chunk
            uint32_t    cnum   = csfip->info.chunk_count.data;     // Number of chunks
            bool        chunks = csfip->info.has_chunk;            // True if we have more than one chunk.


            std::cout << "[Server]{" << client->name << "} Receiving file." << std::endl;
            std::cout << "[Server]{" << client->name << "} File Name -> '" << fname << "'." << std::endl;
            std::cout << "[Server]{" << client->name << "} File Size -> "  << flen  << "."  << std::endl;
#ifdef GULTRA_DEBUG
            if(chunks) {
                std::cout << "[Server]{" << client->name << "} Chunk Len  -> " << clen << "." << std::endl;
                std::cout << "[Server]{" << client->name << "} Chunk Last -> " << clsz << "." << std::endl;
                std::cout << "[Server]{" << client->name << "} Chunk num  -> " << cnum << "." << std::endl;
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
                std::cout << "[Server]{" << client->name << "} Can't open file." << std::endl;

                // This send a PT_ABORT_OPERATION packet wich signal the client it must abort the current operation
                // because this server can't continue it.
                server_abort_operation(org, client);

                goto clientloop_continue;
            }

            if(chunks)
            {
                // We have cnum chunks to receive.

#ifdef GULTRA_DEBUG
                std::cout << "[Server]{" << client->name << "} Receiving File chunks." << std::endl;
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
                        std::cout << "[Server]{" << client->name << "} Can't receive correct chunk." << std::endl;
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
                        std::cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << std::endl;
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
                        std::cout << "[Server]{" << client->name << "} Written chunk n°" << chunk_num << " -> " << clsz << " bytes." << std::endl;
#endif // GULTRA_DEBUG

                    }

                    // Write normal chunk
                    else
                    {
                        ofs.write(chunk->chunk, clen);
                        sz += clen;

#ifdef GULTRA_DEBUG
                        std::cout << "[Server]{" << client->name << "} Written chunk n°" << chunk_num << " -> " << clen << " bytes." << std::endl;
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
                    std::cout << "[Server]{" << client->name << "} Can't receive correct chunk." << std::endl;
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
                    std::cout << "[Server]{" << client->name << "} Can't reinterpret correct chunk." << std::endl;
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
                std::cout << "[Server] Written chunk -> " << flen << " bytes." << std::endl;
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
        SOCKADDR_IN csin = { 0 };
        size_t sin_size = sizeof(csin);
#ifdef _LINUX
        int csock = accept(server->sock, (SOCKADDR*) &csin, (unsigned int*) &sin_size);
#elif defined _WIN32
        int csock = accept(server->sock, (SOCKADDR*) &csin, (int*) &sin_size);
#endif // defined
        if(csock == SOCKET_ERROR)
        {
            std::cerr << "[Server] Can't accept client !" << std::endl;
            return (void*) errno;
        }

        std::cout << "[Server] Receiving new Client connection." << std::endl;
        Packet* pclient = receive_client_packet(csock);
        if(!pclient)
        {
            std::cerr << "[Server] Client disconnected before establishing connection." << std::endl;
            continue;
        }
        else
        {

            if(pclient->m_type == PT_CLIENT_INFO)
            {
#ifdef GULTRA_DEBUG
                std::cout << "[Server] Getting infos from new client." << std::endl;
#endif // GULTRA_DEBUG

                ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(pclient);

#ifdef GULTRA_DEBUG
                std::cout << "[Server] ID     = '" << cip->info.id.data     << "'." << std::endl;
                std::cout << "[Server] IDret  = '" << cip->info.idret.data  << "'." << std::endl;
                std::cout << "[Server] Name   = '" << cip->info.name        << "'." << std::endl;
                std::cout << "[Server] S Port = '" << cip->info.s_port.data << "'." << std::endl;
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
                        std::cout << "[Server] Can't mirror connection to client '" << cip->info.name << "'." << std::endl;
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
                        std::cout << "[Server] Can't send packet 'PT_CLIENT_INFO' to client '" << new_client.name << "'." << std::endl;

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

                    // We now send the PT_CONNECTION_ESTABLISHED packet and create the client thread.
                    server_create_client_thread_loop(server, cclient);
                    server->client_send(cclient->mirror, PT_CLIENT_ESTABLISHED, NULL, 0);

                    // If everything is alright, we can tell user
                    std::cout << "[Server] New Client connected (name = '" << cclient->name << "', id = '" << cclient->mirror->id.data << "')." << std::endl;
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
                    std::cout << "[Server] Received Public Key from client '" << new_client->name << "' : " << std::endl;
                    std::cout << std::string(reinterpret_cast<const char*>(new_client->pubkey.buf), new_client->pubkey.size) << std::endl;
#endif // GULTRA_DEBUG

                    // Once complete we create the thread
                    server_create_client_thread_loop(server, new_client);

                    // Now the pointed client should send us a PT_CLIENT_ESTABLISHED packet.
                }

            }
            else if(pclient->m_type == PT_CLIENT_NAME)
            {
                std::cout << "[Server] Packet 'PT_CLIENT_NAME' is deprecated. Please tell your client to update his GangTella application." << std::endl;
                continue;
            }
            else
            {
                std::cerr << "Client didn't send correct packet ! ( " << (int) pclient->m_type << " )." << std::endl;
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
        std::cout << "[Server] Can't create client connection for adress '" << adress << ":" << (uint32_t) port << "'." << std::endl;

        delete mirror;
        return GERROR_INVALID_CONNECT;
    }

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Creating org client." << std::endl;
#endif // GULTRA_DEBUG

    // Once the mirror is created, we create the original client
    client_t new_client;
    new_client.id.data = 0;
    new_client.mirror  = mirror;
    new_client.server  = server;
    new_client.sock    = SOCKET_ERROR;

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Registering org client." << std::endl;
#endif // GULTRA_DEBUG

    gthread_mutex_lock(&server->mutex);
    {
        // We register the client to the server
        server->clients.push_back(new_client);
        server->client_by_id[new_client.mirror->id.data] = & (server->clients.at(server->clients.size() - 1));
    }
    gthread_mutex_unlock(&server->mutex);

#ifdef GULTRA_DEBUG
    std::cout << "[Server] Sending client info." << std::endl;
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
    std::cout << "[Server] Client inited." << std::endl;
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

            server->clients.erase(server->clients.begin() + server_find_client_index_private_(server, client_name));
            server->client_by_id[id] = nullptr;
            gthread_mutex_unlock(&server->mutex);
        }
    }
}

GEND_DECL

