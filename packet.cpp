/*
    File        : packet.cpp
    Description : Implementation of packet transmission.
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

GBEGIN_DECL

/* ******************************************************************* */

template <> send_file_t serialize(const send_file_t& src)
{
    send_file_t sft;
    sft.lenght         = serialize<size_nt>(src.lenght);
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
    sft.lenght         = deserialize<size_nt>(src.lenght);
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

/** @brief Allocate memory for given type of packet.
 *
 *  @note
 *  This packet will have to be destroyed using the delete
 *  function.
 *
 *  @return
 *  - nullptr if type is PT_UNKNOWN.
 *  - A valid pointer for other cases. As certain Packet doesn't need
 *  a subclass, a valid pointer to Packet* is returned.
**/
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
    case PT_HTTP_REQUEST:
        return new HttpRequestPacket();
	case PT_USER_INIT:
		return new UserInitPacket();
	case PT_USER_INIT_RESPONSE:
		return new UserInitRPacket();
    default:
        return new Packet();
    }
}

/** @brief Receive a client packet.
 *
 *  @note
 *  This function is a low-level function.
 *  @note
 *  It is a blocking function. Untill the client send a packet
 *  to this host, it will wait for something to receive.
 *
 *  @param sock : Socket to receive the packet.
 *  @return nullptr on failure, a pointer to the newly received packet.
 *  This packet must be destroyed using delete.
**/
Packet* receive_client_packet(SOCKET sock)
{
    if(!sock)
        return NULL;

    PacketTypePacket ptp;

    // Receive data
    data_t max_request[8196];
    size_t n = recv(sock, max_request, sizeof(ptp), 0);

    // Receive the PT_PACKETTYPE packet first.
    memcpy((void*) &ptp, max_request, sizeof(ptp));

    if(ptp.m_type != PT_PACKETTYPE &&
       n > 0)
    {
        n = recv(sock, max_request + sizeof(ptp), 8196 - sizeof(ptp), 0);

        // This might be an http request, so transform it to a
        // HttpRequestPacket and receive all sending request.
        HttpRequestPacket* retv = reinterpret_cast<HttpRequestPacket*>(packet_choose_policy(PT_HTTP_REQUEST));
        // Copy data to buffer
        memcpy(retv->request, (char*) max_request, n);

#ifdef GULTRA_DEBUG
        cout << "[Packet] HTTP Request size = " << n << endl;
#endif // GULTRA_DEBUG

        // Return it
        return retv;
    }

    // We construct the packet depending on his type.
    Packet* packet = packet_choose_policy(ptp.type);
    if(!packet)
        return nullptr;
    
    data_t* data   = nullptr;
    size_t len     = packet->getPacketSize();

    if(len > 0)
    {
        data = (data_t*) malloc(len);
        memset(data, 0, len);
        len = recv(sock, data, len, 0);
    }

    // Interpret the packet
    gerror_t err = packet_interpret(ptp.type, packet, data, len);
    if(err != GERROR_NONE)
    {
        // Destroy the packet
        delete packet;
        packet = nullptr;

        // Show the error
#ifdef GULTRA_DEBUG
        cout << "[Packet] Can't interpret packet : " << gerror_to_string(err) << endl;
#endif // GULTRA_DEBUG
    }

    // Clean
    if(data)
        free(data);
    return packet;
}

/** @brief Interpret given packet of given type using given data of lenght len.
 *
 *  @note
 *  Packet deserialization is made in this function. You do not have to deserialize
 *  data coming from this function.
 *
 *  @param type : Packet type to interpret.
 *  @param packet : Pointer to an allocated packet structure using packet_choose_policy() with
 *  right type. This pointer will have his data changed during the process.
 *  @param data : Pointer to a bytesfield of data. This data must represent the exact data of the Packet.
 *  @note It may be null for some Packets.
 *  @param len : Lenght of the data. This lenght must be equal to the Packet data size.
 *
 *  @return
 *  - GERROR_NONE on success
 *  - GERROR_BADARGS if one of the argues is invalid.
**/
gerror_t packet_interpret(const uint8_t type, Packet* packet, data_t* data, size_t len)
{
    if(type == PT_UNKNOWN || !packet)
        return GERROR_BADARGS;

    if(len != packet->getPacketSize())
        return GERROR_BADARGS;

    if(type == PT_CLIENT_NAME)
    {
        ClientNamePacket* cnp = reinterpret_cast<ClientNamePacket*>(packet);
        memcpy(cnp->buffer, data, len);

        cnp->buffer[len] = '\0';
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_MESSAGE)
    {
        ClientMessagePacket* cnp = reinterpret_cast<ClientMessagePacket*>(packet);
        memcpy(cnp->buffer, data, len);

        cnp->buffer[len] = '\0';
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_INFO)
    {
        ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(packet);
        memcpy(&(cip->info), data, len);
        cip->info = deserialize<client_info_t>(cip->info);
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_CLOSING_CONNECTION)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_CLOSING_CONNECTION;
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_ESTABLISHED)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_ESTABLISHED;
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_SENDFILE_INFO)
    {
        ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(packet);
        memcpy(&(csfip->info), data, len);
        csfip->info = deserialize<send_file_t>(csfip->info);
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_SENDFILE_CHUNK)
    {
        ClientSendFileChunkPacket* csfcp = reinterpret_cast<ClientSendFileChunkPacket*>(packet);
        memcpy(csfcp->chunk, data, len);
        return GERROR_NONE;
    }

    else if(type == PT_CLIENT_SENDFILE_TERMINATE)
    {
        Packet* ccp = packet;
        ccp->m_type = PT_CLIENT_SENDFILE_TERMINATE;
        return GERROR_NONE;
    }

    else if(type == PT_ENCRYPTED_INFO)
    {
        EncryptedInfoPacket* eip = reinterpret_cast<EncryptedInfoPacket*>(packet);
        memcpy(&(eip->info), data, len);
        eip->info = deserialize<encrypted_info_t>(eip->info);
        return GERROR_NONE;
    }

    else if(type == PT_ENCRYPTED_CHUNK)
    {
        EncryptedChunkPacket* ecp = reinterpret_cast<EncryptedChunkPacket*>(packet);
        memcpy(&(ecp->chunk), data, len);
        return GERROR_NONE;
    }
    
    else if(type == PT_USER_INIT)
	{
		UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(packet);
		memcpy(&(uip->data), data, len);
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_INIT_RESPONSE)
	{
		UserInitRPacket* uip = reinterpret_cast<UserInitRPacket*>(packet);
		memcpy(&(uip->data), data, len);
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_INIT_NOTACCEPTED)
	{
		packet->m_type = PT_USER_INIT_NOTACCEPTED;
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_INIT_NOTLOGGED)
	{
		packet->m_type = PT_USER_INIT_NOTLOGGED;
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_INIT_AEXIST)
	{
		packet->m_type = PT_USER_INIT_AEXIST;
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_END)
	{
		packet->m_type = PT_USER_END;
		return GERROR_NONE;
	}
	
	else if(type == PT_USER_END_RESPONSE)
	{
		packet->m_type = PT_USER_END_RESPONSE;
		return GERROR_NONE;
	}

    cout << "[Packet] Unknown packet type received : '" << (uint32_t) type << "'." << endl;
    return GERROR_INVALID_PACKET;
}

/** @brief Send a packet to given host using given socket.
 *
 *  @note
 *  This function is a low-level function. Use client_send_packet instead.
 *
 *  @note
 *  You should create the packet then use the packet_get_buffer() function to
 *  get a standard buffer to your packet. Send this buffer using this function
 *  or the client_send_packet() with data as your buffer and sz as the size
 *  of the buffer.
 *
 *  @param sock        : Socket to send the packet.
 *  @param packet_type : Type of the packet to send.
 *  @param data        : Data to send, corresponding to the exact byte pattern
 *  of the packet.
 *  @param sz          : size of the data to send.
 *
 *  @return
 *  - GERROR_NONE on success.
 *  - GERROR_BADARGS if sock is null or if packet_type is invalid.
 *  - GERROR_CANT_SEND_PACKET if recv() function fails.
**/
gerror_t send_client_packet(SOCKET sock, uint8_t packet_type, const void* data, size_t sz)
{
    if(!sock)
        return GERROR_BADARGS;
    if(packet_type == PT_UNKNOWN)
        return GERROR_BADARGS;

    // Send the PT_PACKETTYPE first
    PacketTypePacket ptp(packet_type);
    if(send(sock, (data_t*) &ptp, ptp.getPacketSize(), 0) < 0)
    {
        cout << "[Packet] Can't send PT_PACKETTYPE." << endl;
        return GERROR_CANT_SEND_PACKET;
    }

    // Send the data if any.
    if(sz > 0 && data != NULL)
    {
        if(send(sock, (data_t*) data, sz, 0) < 0)
        {
            std::cerr << "[Packet] Can't send data packet." << endl;
            return GERROR_CANT_SEND_PACKET;
        }
    }

    return GERROR_NONE;
}

/** @brief Return an unsigned char* buffer and give the size
 *  of this buffer from given packet.
**/
gerror_t packet_get_buffer(Packet* p, data_t*& buf, size_t& sz)
{
    if(p)
    {
        buf = reinterpret_cast<data_t*>(p) + sizeof(Packet);
        sz  = p->getPacketSize();
        return GERROR_NONE;
    }
    else
    {
        buf = nullptr;
        sz  = 0;
        return GERROR_BADARGS;
    }
}

GEND_DECL
