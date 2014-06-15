/*
    This file is part of the GangTella project.
*/

#include "packet.h"

GBEGIN_DECL

/* ******************************************************************* */

template <> send_file_t serialize(const send_file_t& src)
{
    send_file_t sft;
    sft.lenght         = serialize<uint32_nt>(src.lenght);
    sft.chunk_lenght   = serialize<uint32_nt>(src.chunk_lenght);
    sft.chunk_lastsize = serialize<uint32_nt>(src.chunk_lastsize);
    sft.chunk_count    = serialize<uint32_nt>(src.chunk_count);
    sft.has_chunk      = src.has_chunk;
    memcpy(sft.name, src.name, SERVER_MAXBUFSIZE);
    return sft;
}

template <> send_file_t deserialize(const send_file_t& src)
{
    send_file_t sft;
    sft.lenght         = deserialize<uint32_nt>(src.lenght);
    sft.chunk_lenght   = deserialize<uint32_nt>(src.chunk_lenght);
    sft.chunk_lastsize = deserialize<uint32_nt>(src.chunk_lastsize);
    sft.chunk_count    = deserialize<uint32_nt>(src.chunk_count);
    sft.has_chunk      = src.has_chunk;
    memcpy(sft.name, src.name, SERVER_MAXBUFSIZE);
    return sft;
}

/* ******************************************************************* */

Packet* receive_client_packet(SOCKET sock, size_t min_packet_size)
{
    if(!sock)
        return NULL;

    PacketTypePacket ptp;
    int n = recv(sock, (char*) &ptp, ptp.getMaxPacketSize(), 0);
    if((unsigned int) n !=  ptp.getMaxPacketSize())
    {
        std::cerr << "Can't receive packet type from socket " << sock << "." << std::endl;
        return NULL;
    }

    if(ptp.type == PT_CLIENT_NAME)
    {
        ClientNamePacket* cnp = new ClientNamePacket();
        char buffer[SERVER_MAXBUFSIZE];
        n = recv(sock, buffer, cnp->getMaxPacketSize(), 0);
        if(n == 0)
        {
            std::cerr << "Can't receive ClientNamePacket from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else if((unsigned int) n < min_packet_size)
        {
            std::cerr << "Can't receive enough bytes from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else
        {
            memcpy(cnp->buffer, buffer, SERVER_MAXBUFSIZE - 1);
            cnp->buffer[n] = '\0';
            return cnp;
        }
    }
    else if(ptp.type == PT_CLIENT_MESSAGE)
    {
        ClientMessagePacket* cnp = new ClientMessagePacket();
        char buffer[SERVER_MAXBUFSIZE];
        n = recv(sock, buffer, cnp->getMaxPacketSize(), 0);
        if(n == 0)
        {
            std::cerr << "Can't receive ClientMessagePacket from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else if((unsigned int) n < min_packet_size)
        {
            std::cerr << "Can't receive enough bytes from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else
        {
            memcpy(cnp->buffer, buffer, SERVER_MAXBUFSIZE - 1);
            cnp->buffer[n] = '\0';
            return cnp;
        }
    }
    else if(ptp.type == PT_CLIENT_CLOSING_CONNECTION)
    {
        Packet* ccp = new Packet();
        ccp->m_type = PT_CLIENT_CLOSING_CONNECTION;
        return ccp;
    }
    else if(ptp.type == PT_CLIENT_ESTABLISHED)
    {
        Packet* ccp = new Packet();
        ccp->m_type = PT_CLIENT_ESTABLISHED;
        return ccp;
    }
    else if(ptp.type == PT_CLIENT_SENDFILE_INFO)
    {
        ClientSendFileInfoPacket* csfip = new ClientSendFileInfoPacket();

        n = recv(sock, (char*) &csfip->info, csfip->getMaxPacketSize(), 0);
        csfip->info = deserialize<send_file_t>(csfip->info);

        if(n < (int) csfip->getMaxPacketSize())
        {
            std::cerr << "[Packet] Receiving bad ClientSendFileInfoPacket structure." << std::endl;
            delete csfip;
            return NULL;
        }
        else
        {
            return csfip;
        }
    }
    else if(ptp.type == PT_CLIENT_SENDFILE_CHUNK)
    {
        ClientSendFileChunkPacket* csfcp = new ClientSendFileChunkPacket();
        n = recv(sock, (char*) &(csfcp->chunk), min_packet_size, 0);
        if(n < (int) min_packet_size)
        {
            std::cerr << "[Packet] Receiving bad ClientSendFileChunkPacket structure. Received " << n << "bytes instead of " << min_packet_size << "bytes." << std::endl;
            delete csfcp;
            return NULL;
        }
        else
        {
            return csfcp;
        }
    }
    else if(ptp.type == PT_CLIENT_SENDFILE_TERMINATE)
    {
        Packet* ccp = new Packet();
        ccp->m_type = PT_CLIENT_SENDFILE_TERMINATE;
        return ccp;
    }

    std::cout << "[Packet] Unknown packet type received : " << (uint32_t) ptp.type << ".";
    return NULL;
}

gerror_t send_client_packet(SOCKET sock, uint8_t packet_type, const void* data, size_t sz)
{
    if(!sock)
        return GERROR_BADARGS;
    if(packet_type == PT_UNKNOWN)
        return GERROR_BADARGS;

    PacketTypePacket ptp;
    ptp.type = packet_type;
    if(send(sock, (char*) &ptp, sizeof(ptp), 0) < 0)
    {
        std::cerr << "[Packet] Can't send initiation packet." << std::endl;
        return GERROR_CANT_SEND_PACKET;
    }

    if(sz > 0 && data != NULL)
    {
        if(send(sock, (const char*) data, sz, 0) < 0)
        {
            std::cerr << "[Packet] Can't send data packet." << std::endl;
            return GERROR_CANT_SEND_PACKET;
        }
    }

    return GERROR_NONE;
}

GEND_DECL
