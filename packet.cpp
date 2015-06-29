/*
    File        : packet.cpp
    Description : Implementation of packet transmission.
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

#include "packet.h"

GBEGIN_DECL

/* ******************************************************************* */

template <> send_file_t serialize(const send_file_t& src)
{
    send_file_t sft;
    sft.lenght         = serialize<size_t>(src.lenght);
    sft.chunk_lenght   = serialize<uint32_t>(src.chunk_lenght);
    sft.chunk_lastsize = serialize<uint32_t>(src.chunk_lastsize);
    sft.chunk_count    = serialize<uint32_t>(src.chunk_count);
    sft.has_chunk      = src.has_chunk;
    memcpy(sft.name, src.name, SERVER_MAXBUFSIZE);
    return sft;
}

template <> send_file_t deserialize(const send_file_t& src)
{
    send_file_t sft;
    sft.lenght         = deserialize<size_t>(src.lenght);
    sft.chunk_lenght   = deserialize<uint32_t>(src.chunk_lenght);
    sft.chunk_lastsize = deserialize<uint32_t>(src.chunk_lastsize);
    sft.chunk_count    = deserialize<uint32_t>(src.chunk_count);
    sft.has_chunk      = src.has_chunk;
    memcpy(sft.name, src.name, SERVER_MAXBUFSIZE);
    return sft;
}

template <> client_info_t serialize(const client_info_t& src)
{
    client_info_t cit;
    cit.id     = serialize<uint32_t>(src.id);
    cit.idret  = serialize<uint32_t>(src.idret);
    cit.s_port = serialize<uint32_t>(src.s_port);
    memcpy(cit.name, src.name, SERVER_MAXBUFSIZE);
    buffer_copy(cit.pubkey, src.pubkey);
    return cit;
}

template <> client_info_t deserialize(const client_info_t& src)
{
    client_info_t cit;
    cit.id     = deserialize<uint32_t>(src.id);
    cit.idret  = deserialize<uint32_t>(src.idret);
    cit.s_port = deserialize<uint32_t>(src.s_port);
    memcpy(cit.name, src.name, SERVER_MAXBUFSIZE);
    buffer_copy(cit.pubkey, src.pubkey);
    return cit;
}

template <> encrypted_info_t serialize(const encrypted_info_t& src)
{
    encrypted_info_t eit;
    eit.ptype = src.ptype;
    eit.cryptedblock_number = serialize<uint32_t>(src.cryptedblock_number);
    eit.cryptedblock_lastsz = serialize<uint32_t>(src.cryptedblock_lastsz);
    return eit;
}

template <> encrypted_info_t deserialize(const encrypted_info_t& src)
{
    encrypted_info_t eit;
    eit.ptype = src.ptype;
    eit.cryptedblock_number = deserialize<uint32_t>(src.cryptedblock_number);
    eit.cryptedblock_lastsz = deserialize<uint32_t>(src.cryptedblock_lastsz);
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

/** @brief Receive a client packet with a time out.
 *
 *  This time out is, for now, fixed to 3 seconds. 
 *  If you want to wait untill a new packet come with connection status
 *  management, use packet_wait().
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
Packet* receive_client_packet(SOCKET sock, bool timedout, uint32_t sec)
{
    if(!sock)
        return NULL;
    
    if(timedout)
    {
        // Set timeout to sec seconds.
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec  = sec;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(char*) &tv, sizeof(struct timeval));
    }

    PacketTypePacket ptp;

    // Receive data
    data_t max_request[8196];
    ssize_t n = recv(sock, max_request, sizeof(ptp), 0);
    
    if(n == -1)
    {
        // An error occured
        return nullptr;
    }

    // Receive the PT_PACKETTYPE packet first.
    memcpy((void*) &ptp, max_request, sizeof(ptp));
    
    // Preparing data
    Packet* packet = nullptr;
    bool skipdata = false;

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
        packet = (Packet*) retv;
        skipdata = true;
    }
    
    if(!skipdata)
    {
        // We construct the packet depending on his type.
        packet = packet_choose_policy(ptp.type);
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
    }
    
    // If we are not receiving an answer, we must send an appropriate answer.
    // PT_RECEIVED_BAD if packet is null, or if packet type is PT_UNKNOWN
    // PT_RECEIVED_OK in other cases.
    // 29/04/2015 [Note] : If packet is an Http Request, we must not send the
    //                     first pre-answer.
    
    if(packet)
    {
        if(packet->m_type != PT_HTTP_REQUEST)
        {
            if(packet->m_type != PT_RECEIVED_OK &&
               packet->m_type != PT_RECEIVED_BAD)
            {
                if(packet->m_type != PT_UNKNOWN)
                    send_client_packet(sock, PT_RECEIVED_OK, nullptr, 0);
                else
                    send_client_packet(sock, PT_RECEIVED_BAD, nullptr, 0);
            }
        }
    }
    else
    {
        send_client_packet(sock, PT_RECEIVED_BAD, nullptr, 0);
    }
    
    // Return the packet.
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
    
    if(type >= PT_MAX)
    {
        cout << "[Packet] Unknown packet type received : '" << (uint32_t) type << "'." << endl;
        return GERROR_INVALID_PACKET;
    }
    
    packet->m_type = type;

    if(type == PT_CLIENT_NAME)
    {
        ClientNamePacket* cnp = reinterpret_cast<ClientNamePacket*>(packet);
        memcpy(cnp->buffer, data, len);

        cnp->buffer[len] = '\0';
    }

    else if(type == PT_CLIENT_MESSAGE)
    {
        ClientMessagePacket* cnp = reinterpret_cast<ClientMessagePacket*>(packet);
        memcpy(cnp->buffer, data, len);

        cnp->buffer[len] = '\0';
    }

    else if(type == PT_CLIENT_INFO)
    {
        ClientInfoPacket* cip = reinterpret_cast<ClientInfoPacket*>(packet);
        memcpy(&(cip->info), data, len);
        cip->info = deserialize<client_info_t>(cip->info);
    }

    else if(type == PT_CLIENT_SENDFILE_INFO)
    {
        ClientSendFileInfoPacket* csfip = reinterpret_cast<ClientSendFileInfoPacket*>(packet);
        memcpy(&(csfip->info), data, len);
        csfip->info = deserialize<send_file_t>(csfip->info);
    }

    else if(type == PT_CLIENT_SENDFILE_CHUNK)
    {
        ClientSendFileChunkPacket* csfcp = reinterpret_cast<ClientSendFileChunkPacket*>(packet);
        memcpy(csfcp->chunk, data, len);
    }

    else if(type == PT_ENCRYPTED_INFO)
    {
        EncryptedInfoPacket* eip = reinterpret_cast<EncryptedInfoPacket*>(packet);
        memcpy(&(eip->info), data, len);
        eip->info = deserialize<encrypted_info_t>(eip->info);
    }

    else if(type == PT_ENCRYPTED_CHUNK)
    {
        EncryptedChunkPacket* ecp = reinterpret_cast<EncryptedChunkPacket*>(packet);
        memcpy(&(ecp->chunk), data, len);
    }
    
    else if(type == PT_USER_INIT)
	{
		UserInitPacket* uip = reinterpret_cast<UserInitPacket*>(packet);
		memcpy(&(uip->data), data, len);
	}
	
	else if(type == PT_USER_INIT_RESPONSE)
	{
		UserInitRPacket* uip = reinterpret_cast<UserInitRPacket*>(packet);
		memcpy(&(uip->data), data, len);
	}
    
    return GERROR_NONE;
}

/** @brief Wait for a packet to come.
 *  
 *  This is a blocking function. It waits untill a packet is received. 
 *  Everytimes the recv function timed out, it send a Connection Status packet
 *  to check validity of the connection.
 *
 *  @param sock : Socket to wait.
 *  @param retpacket : A pointer to null.
**/
gerror_t packet_wait(SOCKET sock, PacketPtr& retpacket)
{
    if(!sock || retpacket != nullptr)
        return GERROR_BADARGS;
    
    while (!retpacket)
    {
        // First we wait 3 seconds for a packet to come.
        retpacket = receive_client_packet(sock);
        
        if(retpacket)
        {
            // If we received a packet, we can return.
            return GERROR_NONE;
        }
        
        else
        {
            // If nothing has been received, just send a connection status packet
            // to check connection with the socket.
            gerror_t err = send_client_packet(sock, PT_CONNECTIONSTATUS, nullptr, 0);
            if(err != GERROR_NONE)
            {
#ifdef GULTRA_DEBUG
                cout << "[Packet] Error sending connection status : " << gerror_to_string(err) << endl;
#endif
                // If we can't have any answer, return the error.
                return err;
            }
            else
            {
                // In debug mode, notifiate we send correctly the checking status.
#ifdef GULTRA_DEBUG
                cout << "[Packet] Checked connection status with SOCK '" << sock << "' OK." << endl;
#endif
            }
        }
    }
    
    return GERROR_NONE;
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
    
    // If packet sent is not an answer, we must wait for a correct
    // answer from the socket, wich may be of type PT_RECEIVED_OK
    // or PT_RECEIVED_BAD.
    
    gerror_t ret = GERROR_NONE;
    
    if(packet_type != PT_RECEIVED_BAD &&
       packet_type != PT_RECEIVED_OK)
    {
        // Wait for the answer packet.
        // If packet sent is PT_USER_INIT, we don't set any time out as it recquire a
        // prompt from user.
        
        Packet* panswer = nullptr;
        
        if(packet_type == PT_USER_INIT)
            panswer = receive_client_packet(sock, false);
        else
            panswer = receive_client_packet(sock);
        
        if(panswer)
        {
            if(panswer->m_type == PT_RECEIVED_OK)
            {
                ret = GERROR_NONE;
            }
            else if(panswer->m_type == PT_RECEIVED_BAD)
            {
                ret = GERROR_ANSWER_BAD;
            }
            else
            {
                ret = GERROR_ANSWER_INVALID;
            }
        }
        else
        {
            ret = GERROR_ANSWER_INVALID;
        }
    }

    return ret;
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
