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

template <> client_info_t serialize(const client_info_t& src)
{
    client_info_t cit;
    cit.id     = serialize<uint32_nt>(src.id);
    cit.idret  = serialize<uint32_nt>(src.idret);
    cit.s_port = serialize<uint32_nt>(src.s_port);
    memcpy(cit.name, src.name, SERVER_MAXBUFSIZE);
    buffer_copy(cit.pubkey, src.pubkey);
    return cit;
}

template <> client_info_t deserialize(const client_info_t& src)
{
    client_info_t cit;
    cit.id     = deserialize<uint32_nt>(src.id);
    cit.idret  = deserialize<uint32_nt>(src.idret);
    cit.s_port = deserialize<uint32_nt>(src.s_port);
    memcpy(cit.name, src.name, SERVER_MAXBUFSIZE);
    buffer_copy(cit.pubkey, src.pubkey);
    return cit;
}

template <> encrypted_info_t serialize(const encrypted_info_t& src)
{
    encrypted_info_t eit;
    eit.ptype = src.ptype;
    eit.cryptedblock_number = serialize<uint32_nt>(src.cryptedblock_number);
    eit.cryptedblock_lastsz = serialize<uint32_nt>(src.cryptedblock_lastsz);
    return eit;
}

template <> encrypted_info_t deserialize(const encrypted_info_t& src)
{
    encrypted_info_t eit;
    eit.ptype = src.ptype;
    eit.cryptedblock_number = deserialize<uint32_nt>(src.cryptedblock_number);
    eit.cryptedblock_lastsz = deserialize<uint32_nt>(src.cryptedblock_lastsz);
    return eit;
}

/* ******************************************************************* */

Packet* packet_choose_policy(const int type)
{
    switch (type)
    {
    case PT_UNKNOWN:
        return nullptr;
    case PT_PACKETTYPE:
        return new PacketTypePacket();
    case PT_CLIENT_NAME:
        return new ClientNamePacket();
    case PT_CLIENT_MESSAGE:
        return new ClientMessagePacket();
    case PT_CLIENT_SENDFILE_INFO:
        return new ClientSendFileInfoPacket();
    case PT_CLIENT_SENDFILE_CHUNK:
        return new ClientSendFileChunkPacket();
    case PT_CLIENT_INFO:
        return new ClientInfoPacket();
    case PT_ENCRYPTED_INFO:
        return new EncryptedInfoPacket();
    case PT_ENCRYPTED_CHUNK:
        return new EncryptedChunkPacket();
    default:
        return new Packet();
    }
}

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

    const int ptype = ptp.type;
    Packet* packet = packet_choose_policy(ptype);
    unsigned char* data = nullptr;
    size_t len = packet->getMaxPacketSize();

    if(len > 0)
    {
        data = (unsigned char*) malloc(len);
#ifdef _LINUX
        len = recv(sock, (unsigned char*) data, len, 0);
#elif defined _WIN32
        len = recv(sock, (char*) data, len, 0);
#endif // defined
    }

    return packet_interpret(sock, ptype, packet, data, len);
}

Packet* packet_interpret(SOCKET sock, const uint8_t type, Packet* packet, unsigned char* data, size_t len)
{
    size_t min_packet_size = packet->getMaxPacketSize();

    if(type == PT_CLIENT_NAME)
    {
        ClientNamePacket* cnp = reinterpret_cast<ClientNamePacket*>(packet);

        if(len == 0)
        {
            std::cerr << "Can't receive ClientNamePacket from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else if((unsigned int) len < min_packet_size)
        {
            std::cerr << "Can't receive enough bytes from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else
        {
            memcpy(cnp->buffer, data, SERVER_MAXBUFSIZE - 1);
            cnp->buffer[len] = '\0';
            return cnp;
        }
    }
    else if(type == PT_CLIENT_MESSAGE)
    {
        ClientMessagePacket* cnp = reinterpret_cast<ClientMessagePacket*>(packet);

        if(len == 0)
        {
            std::cerr << "Can't receive ClientMessagePacket from socket " << sock << "." << std::endl;
            delete cnp;
            return NULL;
        }
        else
        {
            memcpy(cnp->buffer, data, len);
            cnp->buffer[len] = '\0';
            return cnp;
        }
    }
    else if(type == PT_CLIENT_INFO)
    {
        ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(packet);

        if(len == 0)
        {
#ifdef GULTRA_DEBUG
            std::cout << "[Packet] Received Bad 'PT_CLIENT_INFO' packet." << std::endl;
#endif // GULTRA_DEBUG
            delete cip;
            return nullptr;
        }

        memcpy(&(cip->info), data, len);
        return cip;
    }
    else if(type == PT_CLIENT_CLOSING_CONNECTION)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_CLOSING_CONNECTION;
        return ccp;
    }
    else if(type == PT_CLIENT_ESTABLISHED)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_ESTABLISHED;
        return ccp;
    }
    else if(type == PT_CLIENT_SENDFILE_INFO)
    {
        ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(packet);

        if(len < csfip->getMaxPacketSize())
        {
            std::cerr << "[Packet] Receiving bad ClientSendFileInfoPacket structure." << std::endl;
            delete csfip;
            return NULL;
        }
        else
        {
            memcpy(&(csfip->info), data, len);
            csfip->info = deserialize<send_file_t>(csfip->info);
            return csfip;
        }
    }
    else if(type == PT_CLIENT_SENDFILE_CHUNK)
    {
        ClientSendFileChunkPacket* csfcp = reinterpret_cast<ClientSendFileChunkPacket*>(packet);

        if(len == 0 /* || len > min_packet_size */)
        {
            std::cerr << "[Packet] Receiving bad ClientSendFileChunkPacket structure. Received " << len << "bytes instead of " << min_packet_size << "bytes." << std::endl;
            delete csfcp;
            return NULL;
        }
        else
        {
            memcpy(csfcp->chunk, data, len);
            return csfcp;
        }
    }
    else if(type == PT_CLIENT_SENDFILE_TERMINATE)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_SENDFILE_TERMINATE;
        return ccp;
    }

    else if(type == PT_ENCRYPTED_INFO)
    {
        EncryptedInfoPacket* eip = reinterpret_cast<EncryptedInfoPacket*>(packet);

        if(len < min_packet_size)
        {
            std::cout << "[Packet] Can't receive enough byte." << std::endl;
            delete eip;
            return NULL;
        }

        memcpy(&(eip->info), data, len);
        eip->info = deserialize<encrypted_info_t>(eip->info);
        return eip;
    }

    else if(type == PT_ENCRYPTED_CHUNK)
    {
        EncryptedChunkPacket* ecp = reinterpret_cast<EncryptedChunkPacket*>(packet);

        if(len < min_packet_size)
        {
            std::cout << "[Packet] Can't receive enough byte." << std::endl;
            delete ecp;
            return NULL;
        }

        memcpy(&(ecp->chunk), data, len);
        return ecp;
    }

    std::cout << "[Packet] Unknown packet type received : " << (uint32_t) type << ".";
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
