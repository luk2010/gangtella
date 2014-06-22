/*
    This file is part of the GangTella project.
*/
#include "packet.h"
#include "client.h"
#include "server.h"

GBEGIN_DECL

gerror_t client_create(client_t* client, const char* adress, size_t port)
{
    if(!client || !adress || port == 0)
        return GERROR_BADARGS;

    SOCKET sock     = socket(AF_INET, SOCK_STREAM, 0);
    SOCKADDR_IN sin = { 0 };
    struct hostent* hostinfo;

    if(sock == INVALID_SOCKET)
    {
        std::cerr << "[Client] Can't create socket !" << std::endl;
        return GERROR_INVALID_SOCKET;
    }

#ifdef GULTRA_DEBUG
    std::cout << "[Client] Correctly created socket." << std::endl;
#endif // GULTRA_DEBUG

    hostinfo = gethostbyname(adress);
    if(hostinfo == NULL)
    {
        std::cerr << "[Client] Unknown host " << adress << "." << std::endl;

        closesocket(sock);
        return GERROR_INVALID_HOST;
    }

    sin.sin_addr   = *(IN_ADDR*) hostinfo->h_addr;
    sin.sin_port   = htons(port);
    sin.sin_family = AF_INET;

#ifdef GULTRA_DEBUG
    std::cout << "[Client] Correctly created hostinfo." << std::endl;
#endif // GULTRA_DEBUG

    if(connect(sock, (SOCKADDR*) &sin, sizeof(SOCKADDR)) == SOCKET_ERROR)
    {
        std::cerr << "[Client] Can't connect to host '" << adress << ":" << port << "'." << std::endl;

        closesocket(sock);
        return GERROR_INVALID_CONNECT;
    }

    std::cout << "[Client] Connected to host '" << adress << ":" << port << "'." << std::endl;
    std::cout << "[Client] Name = '" << client->name << "'." << std::endl;
    client->sock    = sock;
    client->address = sin;

    return GERROR_NONE;
}

gerror_t client_send_packet(client_t* client, uint8_t packet_type, const void* data, size_t sz)
{
    return send_client_packet(client->sock, packet_type, data, sz);
}

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
    std::cout << "[Client] Closed client '" << client->name << "'." << std::endl;
#endif // GULTRA_DEBUG

    return ret;
}

gerror_t client_send_cryptpacket(client_t* client, uint8_t packet_type, const void* data, size_t sz)
{
    // First we have to create the EncryptionInfoPacket

    server_t* server = (server_t*) client->server;
    encrypted_info_t info;
    info.ptype                    = packet_type;

    if(sz > 0) {
        info.cryptedblock_number.data = (sz / (RSA_SIZE - 11) ) + 1;
        info.cryptedblock_lastsz.data = sz % (RSA_SIZE - 11);
    }
    else {
        info.cryptedblock_number.data = 0;
        info.cryptedblock_lastsz.data = 0;
    }

#ifdef GULTRA_DEBUG
    std::cout << "[Client] Sending CryptPacket Info (Block Num = " << info.cryptedblock_number.data << ", LBS = " << info.cryptedblock_lastsz.data << ")." << std::endl;
#endif // GULTRA_DEBUG

    // We send the info to client
    info = serialize<encrypted_info_t>(info);
    gerror_t err = client_send_packet(client, PT_ENCRYPTED_INFO, &info, sizeof(encrypted_info_t));
    info = deserialize<encrypted_info_t>(info);

    if(err != GERROR_NONE)
        return err;

    if(info.cryptedblock_number.data > 1)
    {
        // We have to send many crypted chunk
        unsigned char* chunk   = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* current = nullptr;
        unsigned char* to      = (unsigned char*) malloc(RSA_SIZE);
        unsigned int i = 0;
        for (; i < info.cryptedblock_number.data - 1; ++i)
        {
            current = chunk + ( i * ( RSA_SIZE - 11 ) );
            int len = Encryption::crypt(server->crypt, to, current, RSA_SIZE - 11);
            client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);
        }

        current = chunk + ( i * ( RSA_SIZE - 11 ) );
        int len = Encryption::crypt(server->crypt, to, current, info.cryptedblock_lastsz.data);
        client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);

        // Terminated !
        free(to);
        return GERROR_NONE;
    }
    else if(info.cryptedblock_number.data == 1)
    {
        // We have to send one crypted chunk
        unsigned char* chunk = reinterpret_cast<unsigned char*>(const_cast<void*>(data));
        unsigned char* to    = (unsigned char*) malloc(RSA_SIZE);

        int len = Encryption::crypt(server->crypt, to, chunk, RSA_SIZE - 11);
        client_send_packet(client, PT_ENCRYPTED_CHUNK, to, len);

        // Terminated !
        return GERROR_NONE;
    }

    return GERROR_NONE;
}

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
        const int lenght = is.tellg();
        is.seekg(0, is.beg);

        std::cout << "[Client] Sending file '" << filename << "'." << std::endl;

#ifdef GULTRA_DEBUG
        struct timespec st = timer_start();
#endif // GULTRA_DEBUG

        if(lenght < SERVER_MAXBUFSIZE)
        {
            // On peut envoyer le fichier d'un seul block
            struct send_file_t sft;
            sft.has_chunk   = false;
            sft.lenght.data = lenght;

            const int flenght = strlen(filename);
            memcpy(sft.name, filename, flenght);
            sft.name[flenght] = '\0';

#ifdef GULTRA_DEBUG
            std::cout << "[Client] Info : " << std::endl;
            std::cout << "[Client] lenght      = " << lenght << "." << std::endl;
            std::cout << "[Client] Chunk count = 1." << std::endl;
#endif // GULTRA_DEBUG

            sft = serialize<send_file_t>(sft);
            {
                if(server->client_send(client, PT_CLIENT_SENDFILE_INFO, &sft, sizeof(struct send_file_t)) != GERROR_NONE)
                {
                    std::cout << "[Client] Error sending info packet !" << std::endl;

                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }
            }
            sft = deserialize<send_file_t>(sft);

            // On lit le fichier dans un buffer de la bonne taille
            char buffer[lenght+1];
            is.read(buffer, lenght);
            if(!is)
            {
                std::cout << "[Client] Can't read file '" << filename << "'." << std::endl;
                server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0);

                is.close();
                return GERROR_IO_CANTREAD;
            }

#ifdef GULTRA_DEBUG
            std::cout << "[Client] Sending chunk (size : " << lenght << ", # = 1)." << std::endl;
#endif // GULTRA_DEBUG

            // On envoie le tout
            if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, buffer, lenght) != GERROR_NONE)
            {
                std::cout << "[Client] Error sending chunk packet !" << std::endl;

                is.close();
                return GERROR_CANT_SEND_PACKET;
            }

#ifdef GULTRA_DEBUG
            std::cout << "[Client] Sending File termination packet." << std::endl;
#endif // GULTRA_DEBUG

            // Et on termine
            if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
            {
                std::cout << "[Client] Error sending terminate packet !" << std::endl;

                is.close();
                return GERROR_CANT_SEND_PACKET;
            }

            is.close();

            std::cout << "[Client] File '" << filename << "' correctly send to client '" << client->name << "'." << std::endl;

#ifdef GULTRA_DEBUG
            long ten = timer_end(st);
            std::cout << "[Client] Time elapsed (microseconds) = " << ten/1000 << "." << std::endl;
#endif // GULTRA_DEBUG

            return GERROR_NONE;
        }
        else
        {
            // Il va falloir envoyer le fichier en plusiers chunk
            struct send_file_t sft;
            sft.has_chunk           = true;
            sft.lenght.data         = lenght;
            sft.chunk_lenght.data   = SERVER_MAXBUFSIZE;
            sft.chunk_lastsize.data = lenght % SERVER_MAXBUFSIZE;
            sft.chunk_count.data    = ((int) lenght/SERVER_MAXBUFSIZE) + 1;

            const int flenght  = strlen(filename);
            memcpy(sft.name, filename, flenght);
            sft.name[flenght]  = '\0';

#ifdef GULTRA_DEBUG
            std::cout << "[Client] Info : " << std::endl;
            std::cout << "[Client] lenght          = " << lenght << "." << std::endl;
            std::cout << "[Client] Chunk count     = " << sft.chunk_count.data << "." << std::endl;
            std::cout << "[Client] Chunk lenght    = " << sft.chunk_lenght.data << "." << std::endl;
            std::cout << "[Client] Chunk last size = " << sft.chunk_lastsize.data << "." << std::endl;
#endif // GULTRA_DEBUG

            sft = serialize<send_file_t>(sft);
            {
                if(server->client_send(client, PT_CLIENT_SENDFILE_INFO, &sft, sizeof(sft)) != GERROR_NONE)
                {
                    std::cout << "[Client] Error sending info packet !" << std::endl;
                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }
            }
            sft = deserialize<send_file_t>(sft);

            uint32_t chunks = 0;
            char buffer[SERVER_MAXBUFSIZE];

            while(chunks < sft.chunk_count.data - 1)
            {
                is.read(buffer, sft.chunk_lenght.data);
                if(!is)
                {
                    std::cout << "[Client] Error : Can't terminate file reading.";
                    is.close();

                    if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
                    {
                        std::cout << "[Client] Error sending terminate packet !" << std::endl;
                        return GERROR_CANT_SEND_PACKET;
                    }
                    return GERROR_IO_CANTREAD;
                }

#ifdef GULTRA_DEBUG
                std::cout << "[Client] Sending chunk (size : " << sft.chunk_lenght.data << ", # = " << chunks << ")." << std::endl;
#endif // GULTRA_DEBUG

                if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, buffer, sft.chunk_lenght.data) != GERROR_NONE)
                {
                    std::cout << "[Client] Error sending chunk packet !" << std::endl;
                    is.close();
                    return GERROR_CANT_SEND_PACKET;
                }

                chunks++;
            }

            is.read(buffer, sft.chunk_lastsize.data);
            if(!is)
            {
                std::cout << "[Client] Error : Can't terminate file reading.";
                is.close();

                if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
                {
                    std::cout << "[Client] Error sending terminate packet !" << std::endl;
                    return GERROR_CANT_SEND_PACKET;
                }
                return GERROR_IO_CANTREAD;
            }

            is.close();

#ifdef GULTRA_DEBUG
            std::cout << "[Client] Sending chunk (size : " << sft.chunk_lastsize.data << ", # = " << chunks << ")." << std::endl;
#endif // GULTRA_DEBUG

            if(server->client_send(client, PT_CLIENT_SENDFILE_CHUNK, buffer, sft.chunk_lastsize.data) != GERROR_NONE)
            {
                std::cout << "[Client] Error sending chunk packet !" << std::endl;
                return GERROR_CANT_SEND_PACKET;
            }
            if(server->client_send(client, PT_CLIENT_SENDFILE_TERMINATE, NULL, 0) != GERROR_NONE)
            {
                std::cout << "[Client] Error sending terminate packet !" << std::endl;
                return GERROR_CANT_SEND_PACKET;
            }

            std::cout << "[Client] File '" << filename << "' correctly send to client '" << client->name << "'." << std::endl;

#ifdef GULTRA_DEBUG
            long ten = timer_end(st);
            std::cout << "[Client] Time elapsed (microseconds) = " << ten/1000 << "." << std::endl;
#endif // GULTRA_DEBUG

            return GERROR_NONE;
        }
    }
    else
    {
        std::cout << "[Client] Error : Can't open file '" << filename << "'.";
        return GERROR_CANTOPENFILE;
    }
}

GEND_DECL
