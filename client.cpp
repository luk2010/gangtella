/*
    File        : client.cpp
    Description : Client related function
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

#include "packet.h"
#include "client.h"
#include "server.h"

GBEGIN_DECL

/** @brief [Internal] Allocates a new client with given id, mirror and server.
 *
 *  @param ret : [out] A pointer to a clientptr_t wich will contains the client
 *  structure. The clientptr_t must be null.
 *  @param id : the id that will be used in the client structure. It must be given
 *  by the server (with a function like @ref server_generate_new_id() ) .
 *  @param mirror : A clientptr_t wich points to an already initialized mirror pointer.
 *  @param cserver : A pointer to the server creator. If null, the server specified will
 *  be the default global one. 
 *
 *  @return 
 *  - GERROR_NONE : Operation succeeded. 
 *  - GERROR_BADARGS : The returned pointer is not null. 
 *  - GERROR_ALLOC : Can't allocate the client structure.
 *
 *  @note This function is generally used internally by the server.
**/
gerror_t client_alloc (clientptr_t* ret, uint32_t id, clientptr_t mirror, void* cserver)
{
    if(*ret != nullptr)
        return GERROR_BADARGS;
    
    clientptr_t client = new client_t;
    if(!client)
    {
#ifdef GULTRA_DEBUG
        cout << "[Client] Can't allocate new client structure." << endl;
#endif
        return GERROR_ALLOC;
    }
    
    client->id      = id;
    client->mirror  = mirror;
    
    if(!cserver)
    {
#ifdef GULTRA_DEBUG
        cout << "[Client] Setting server to default one for client '" << id << "'." << endl;
#endif
        client->server = &server;
    }
    else
    {
        client->server = cserver;
    }
    
    client->logged_user = nullptr;
    
    *ret = client;
    return GERROR_NONE;
}

/** @brief Destroys the given client and free his memory.
**/
gerror_t client_free (clientptr_t* ret)
{
    if(*ret == nullptr)
        return GERROR_BADARGS;
    if((*ret)->server_thread.currope != CO_NONE || (*ret)->sock != INVALID_SOCKET)
    {
#ifdef GULTRA_DEBUG
        cout << "[Client] Client(id=" << (*ret)->id << ") can't be freed as it is not stopped. Please "
        << "call 'client_close(client)' before freeing the client structure." << endl;
#endif
        return GERROR_BADARGS;
    }
    
    if((*ret)->mirror)
    {
        client_free(&(*ret)->mirror);
    }
    
    delete *ret;
    *ret = nullptr;
    return GERROR_NONE;
}

/** @brief Create a Client from given information.
 *
 *  @param client : Pointer to a complete client structure. @note Only fields client_t::name
 *  and client_t::sock are required.
 *  @param adress : A usual IP or domain name to connect.
 *  @param port : The port to use for the connection (server-ide).
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if one of the given args is null.
 *  - GERROR_INVALID_SOCKET if socket is invalid or can't be created.
 *  - GERROR_INVALID_HOST if host is invalid.
 *  - GERROR_INVALID_CONNECT if can't connect to host.
 *  - An error depending on client_send_packet().
**/
gerror_t client_create(client_t* client, const char* adress, size_t port)
{
    if(!client || !adress || port == 0)
        return GERROR_BADARGS;

    SOCKET sock     = socket(AF_INET, SOCK_STREAM, 0);
    SOCKADDR_IN sin;
    struct hostent* hostinfo;

    if(sock == INVALID_SOCKET)
    {
        cout << "[Client] Can't create socket !" << endl;
        return GERROR_INVALID_SOCKET;
    }

#ifdef GULTRA_DEBUG
    cout << "[Client] Correctly created socket." << endl;
#endif // GULTRA_DEBUG

    hostinfo = gethostbyname(adress);
    if(hostinfo == NULL)
    {
        cout << "[Client] Unknown host " << adress << "." << endl;

        closesocket(sock);
        return GERROR_INVALID_HOST;
    }

    sin.sin_addr   = *(IN_ADDR*) hostinfo->h_addr;
    sin.sin_port   = htons(port);
    sin.sin_family = AF_INET;

#ifdef GULTRA_DEBUG
    cout << "[Client] Correctly created hostinfo." << endl;
#endif // GULTRA_DEBUG

    if(connect(sock, (SOCKADDR*) &sin, sizeof(SOCKADDR)) == SOCKET_ERROR)
    {
        cout << "[Client] Can't connect to host '" << adress << ":" << port << "'." << endl;

        closesocket(sock);
        return GERROR_INVALID_CONNECT;
    }

    cout << "[Client] Connected to host '" << adress << ":" << port << "'." << endl;
    cout << "[Client] Name = '" << client->name << "'." << endl;
    client->sock    = sock;
    client->address = sin;

    return GERROR_NONE;
}

/** @brief Send a packet to a given client.
 *  @see send_client_packet() for more details.
 *
 *  @param client : Pointer to the client structure.
 *  @param packet_type : Type of the packet to send.
 *  @param data : Raw data to send.
 *  @param sz : Size of the data to send.
 *
 *  @return
 *  The same as send_client_packet().
**/
gerror_t client_send_packet(client_t* client, uint8_t packet_type, const void* data, size_t sz)
{
    return send_client_packet(client->sock, packet_type, data, sz);
}

/** @brief Close a client connection.
 *  @param send_close_packet : If true, send a PT_CLIENT_CLOSING_CONNECTION packet to
 *  the corresponding socket. This option is used by the server to end mirror connections,
 *  so don't use it or use it at your own risk.
 *
 *  @return
 *  - GERROR_NONE on success
 *  - GERROR_BADARGS if one of the given args is null.
 *  - GERROR_CANT_CLOSE_SOCKET if socket could not be closed.
 *  - @see errors from client_send_packet().
**/
gerror_t client_close(client_t* client, bool send_close_packet)
{
    if(!client)
        return GERROR_BADARGS;

    gerror_t ret = GERROR_NONE;
    if(send_close_packet == true)
    {
        ret = client_send_packet(client, PT_CLIENT_CLOSING_CONNECTION, NULL, 0);
    }

    if(closesocket(client->sock) != 0)
    {
        if(ret == GERROR_NONE)
            ret = GERROR_CANT_CLOSE_SOCKET;
    }

#ifdef GULTRA_DEBUG
    cout << "[Client] Closed client '" << client->name << "'." << endl;
#endif // GULTRA_DEBUG

    return ret;
}

/** @brief Send a crypted packet to a given client.
 *
 *  @param client : Pointer to the client structure.
 *  @param packet_type : Type of the packet to send.
 *  @param data : Raw data to send.
 *  @param sz : Size of the data to send.
 *
 *  @return
 *  - GERROR_NONE if everything turned right.
**/
gerror_t client_send_cryptpacket(client_t* client, uint8_t packet_type, const void* data, size_t sz)
{
    // First we have to create the EncryptionInfoPacket

    server_t* server = (server_t*) client->server;
    encrypted_info_t info;
    info.ptype = packet_type;

    if(sz > 0) {
        info.cryptedblock_number = (uint32_t) (sz / (RSA_SIZE - 11) ) + 1;
        info.cryptedblock_lastsz = (uint32_t) sz % (RSA_SIZE - 11);
    }
    else {
        info.cryptedblock_number = 0;
        info.cryptedblock_lastsz = 0;
    }

#ifdef GULTRA_DEBUG
    cout << "[Client] Sending CryptPacket Info (Block Num = " << info.cryptedblock_number << ", LBS = " << info.cryptedblock_lastsz << ")." << endl;
#endif // GULTRA_DEBUG

    // We send the info to client
    info = serialize<encrypted_info_t>(info);
    gerror_t err = client_send_packet(client, PT_ENCRYPTED_INFO, &info, sizeof(encrypted_info_t));
    info = deserialize<encrypted_info_t>(info);

    if(err != GERROR_NONE)
        return err;

    if(info.cryptedblock_number > 1)
    {
        // We have to send many crypted chunk
        unsigned char* chunk   = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* current = nullptr;
        unsigned char* to      = (unsigned char*) malloc(RSA_SIZE);
        memset(to, 0, RSA_SIZE);

        unsigned int i = 0;
        for (; i < info.cryptedblock_number - 1; ++i)
        {
            current = chunk + ( i * ( RSA_SIZE - 11 ) );
            int len = Encryption::crypt(server->crypt, to, current, RSA_SIZE - 11);

#ifdef GULTRA_DEBUG
            cout << "[Client] Sending len = " << len << "bytes." << endl;
#endif // GULTRA_DEBUG

            client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);
        }

        current = chunk + ( i * ( RSA_SIZE - 11 ) );
        int len = Encryption::crypt(server->crypt, to, current, info.cryptedblock_lastsz);

#ifdef GULTRA_DEBUG
        cout << "[Client] Sending len = " << len << "bytes." << endl;
#endif // GULTRA_DEBUG

        client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);

        // Terminated !
        free(to);

#ifdef GULTRA_DEBUG
        cout << "[Client] Crypt Terminated." << endl;
#endif // GULTRA_DEBUG

        return GERROR_NONE;
    }
    else if(info.cryptedblock_number == 1)
    {
        // We have to send one crypted chunk
        unsigned char* chunk = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* to    = (unsigned char*) malloc(RSA_SIZE);

        int len = Encryption::crypt(server->crypt, to, chunk, RSA_SIZE - 11);
        client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);

        // Terminated !
        free(to);
        return GERROR_NONE;
    }

    return GERROR_NONE;
}


/** @brief Send a file to a given client.
 *
 *  @param filename : A string containing the path to the file to send. This path must
 *  have a size inferior to SERVER_MAXBUFSIZE.
 *
 *  @return
 *  - GERROR_NONE on success
 *  - GERROR_BADARGS if one of the given args is null.
 *  - GERROR_BUFSIZEEXCEEDED if the filename size is superior to the server limit.
 *  - GERROR_CANT_SEND_PACKET if a packet could not be send.
 *  - GERROR_IO_CANTREAD if file couldn't be read.
 *  - GERROR_CANTOPENFILE if file couldn't be opened.
**/
gerror_t client_send_file(client_t* client, const char* filename)
{
    if(client == NULL || filename == NULL || client->server == nullptr)
        return GERROR_BADARGS;

    if(strlen(filename) >= SERVER_MAXBUFSIZE)
        return GERROR_BUFSIZEEXCEEDED;

    server_t* server = (server_t*) client->server;
    std::ifstream is(filename, std::ifstream::binary);
    if(is)
    {
        is.seekg(0, is.end);
        const size_t lenght = is.tellg();
        is.seekg(0, is.beg);

        cout << "[Client] Sending file '" << filename << "'." << endl;

#ifdef GULTRA_DEBUG
        timespec_t st = timer_start();
#endif // GULTRA_DEBUG

        if(lenght < SERVER_MAXBUFSIZE)
        {
            // On peut envoyer le fichier d'un seul block
            struct send_file_t sft;
            sft.has_chunk   = false;
            sft.lenght = lenght;

            const size_t flenght = strlen(filename);
            memcpy(sft.name, filename, flenght);
            sft.name[flenght] = '\0';

#ifdef GULTRA_DEBUG
            cout << "[Client] Info : " << endl;
            cout << "[Client] lenght      = " << lenght << "." << endl;
            cout << "[Client] Chunk count = 1." << endl;
#endif // GULTRA_DEBUG

            sft = serialize<send_file_t>(sft);
            {
                if(server->client_send(client, PT_CLIENT_SENDFILE_INFO, &sft, sizeof(struct send_file_t)) != GERROR_NONE)
                {
                    cout << "[Client] Error sending info packet !" << endl;

                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }
            }

            sft = deserialize<send_file_t>(sft);

            // On lit le fichier dans un buffer de la bonne taille
            size_t len = SERVER_MAXBUFSIZE;
            char data[len];
            is.read(data, lenght);
            if(!is)
            {
                cout << "[Client] Can't read file '" << filename << "'." << endl;
                server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0);

                is.close();
                return GERROR_IO_CANTREAD;
            }

#ifdef GULTRA_DEBUG
            cout << "[Client] Sending chunk (size : " << lenght << ", # = 1)." << endl;
#endif // GULTRA_DEBUG

            // On envoie le tout
            if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, data, len) != GERROR_NONE)
            {
                cout << "[Client] Error sending chunk packet !" << endl;

                is.close();
                return GERROR_CANT_SEND_PACKET;
            }

            server->bs_callback(sft.name, len, lenght);

#ifdef GULTRA_DEBUG
            cout << "[Client] Sending File termination packet." << endl;
#endif // GULTRA_DEBUG

/*
            // Et on termine
            if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
            {
                cout << "[Client] Error sending terminate packet !" << endl;

                is.close();
                return GERROR_CANT_SEND_PACKET;
            }
*/

            is.close();

            cout << "[Client] File '" << filename << "' correctly send to client '" << client->name << "'." << endl;

#ifdef GULTRA_DEBUG
            long ten = timer_end(st);
            cout << "[Client] Time elapsed (microseconds) = " << ten/1000 << "." << endl;
#endif // GULTRA_DEBUG

            return GERROR_NONE;
        }
        else
        {
            // Il va falloir envoyer le fichier en plusiers chunk
            struct send_file_t sft;
            sft.has_chunk      = true;
            sft.lenght         = lenght;
            sft.chunk_lenght   = SERVER_MAXBUFSIZE;
            sft.chunk_lastsize = lenght % SERVER_MAXBUFSIZE;
            sft.chunk_count    = ((int) lenght/SERVER_MAXBUFSIZE) + 1;

            const size_t flenght  = strlen(filename);
            memcpy(sft.name, filename, flenght);
            sft.name[flenght]  = '\0';

#ifdef GULTRA_DEBUG
            cout << "[Client] Info : " << endl;
            cout << "[Client] lenght          = " << lenght << "." << endl;
            cout << "[Client] Chunk count     = " << sft.chunk_count << "." << endl;
            cout << "[Client] Chunk lenght    = " << sft.chunk_lenght << "." << endl;
            cout << "[Client] Chunk last size = " << sft.chunk_lastsize << "." << endl;
#endif // GULTRA_DEBUG

            sft = serialize<send_file_t>(sft);
            {
                if(server->client_send(client, PT_CLIENT_SENDFILE_INFO, &sft, sizeof(sft)) != GERROR_NONE)
                {
                    cout << "[Client] Error sending info packet !" << endl;
                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }
            }
            sft = deserialize<send_file_t>(sft);

            uint32_t chunks = 0;
            size_t len      = sft.chunk_lenght;
            char buffer[len];

            size_t len_send = 0;
            if(server->bs_callback)
                server->bs_callback(sft.name, len_send, lenght);

            while(chunks < sft.chunk_count - 1)
            {
                is.read(buffer, sft.chunk_lenght);
                if(!is)
                {
                    cout << "[Client] Error : Can't terminate file reading.";
                    is.close();

                    if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
                    {
                        cout << "[Client] Error sending terminate packet !" << endl;
                        return GERROR_CANT_SEND_PACKET;
                    }
                    return GERROR_IO_CANTREAD;
                }

#ifdef GULTRA_DEBUG
                cout << "[Client] Sending chunk (size : " << sft.chunk_lenght << ", # = " << chunks << ")." << endl;
#endif // GULTRA_DEBUG

                if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, buffer, sft.chunk_lenght) != GERROR_NONE)
                {
                    cout << "[Client] Error sending chunk packet !" << endl;
                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }

                len_send += len;
                if(server->bs_callback)
                    server->bs_callback(sft.name, len_send, lenght);
                chunks++;
            }

            memset((void*) buffer, 0, len);
            is.read(buffer, sft.chunk_lastsize);
            if(!is)
            {
                cout << "[Client] Error : Can't terminate file reading.";
                is.close();

                if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
                {
                    cout << "[Client] Error sending terminate packet !" << endl;
                    return GERROR_CANT_SEND_PACKET;
                }
                return GERROR_IO_CANTREAD;
            }

            is.close();

#ifdef GULTRA_DEBUG
            cout << "[Client] Sending chunk (size : " << sft.chunk_lastsize << ", # = " << chunks << ")." << endl;
#endif // GULTRA_DEBUG

            if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, buffer, sft.chunk_lenght) != GERROR_NONE)
            {
                cout << "[Client] Error sending chunk packet !" << endl;
                return GERROR_CANT_SEND_PACKET;
            }

            len_send += sft.chunk_lenght;

            if(server->bs_callback)
                server->bs_callback(sft.name, len_send, lenght);

/*
            if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
            {
                cout << "[Client] Error sending terminate packet !" << endl;
                return GERROR_CANT_SEND_PACKET;
            }
*/

            cout << "[Client] File '" << filename << "' correctly send to client '" << client->name << "'." << endl;

#ifdef GULTRA_DEBUG
            long ten = timer_end(st);
            cout << "[Client] Time elapsed (microseconds) = " << ten/1000 << "." << endl;
#endif // GULTRA_DEBUG

            return GERROR_NONE;
        }
    }
    else
    {
        cout << "[Client] Error : Can't open file '" << filename << "'.";
        return GERROR_CANTOPENFILE;
    }
}

gerror_t client_thread_setstatus(clientptr_t client, ClientOperation ope)
{
    gthread_mutex_lock(&client->server_thread.mutexaccess);
    client->server_thread.currope = ope;
    gthread_mutex_unlock(&client->server_thread.mutexaccess);
    return GERROR_NONE;
}

GEND_DECL
