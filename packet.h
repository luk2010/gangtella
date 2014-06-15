/*
    This file is part of the GangTella project.
*/

#ifndef __PACKET__H
#define __PACKET__H

#include "prerequesites.h"

GBEGIN_DECL

/* ******************************************************************* */

/** @brief A structure to help the server to receive files.
**/
struct send_file_t
{
    uint32_nt  lenght;                  ///< @brief File total lenght
    uint32_nt  chunk_lenght;            ///< @brief Non-last chunk lenght
    uint32_nt  chunk_lastsize;          ///< @brief last chunk lenght
    uint32_nt  chunk_count;             ///< @brief Chunk count (including last chunk)
    bool       has_chunk;               ///< @brief Does this file will be send in chunks ?
    char       name[SERVER_MAXBUFSIZE]; ///< @brief File name

    send_file_t& operator = (const send_file_t& src) {
        lenght         = src.lenght;
        chunk_lenght   = src.chunk_lenght;
        chunk_lastsize = src.chunk_lastsize;
        chunk_count    = src.chunk_count;
        has_chunk      = src.has_chunk;
        memcpy(name, src.name, SERVER_MAXBUFSIZE);
        return *this;
    }

} __attribute__((packed));
typedef struct send_file_t send_file_t;

template <> send_file_t serialize(const send_file_t&);
template <> send_file_t deserialize(const send_file_t&);

/* ******************************************************************* */


typedef enum PacketType {
    PT_UNKNOWN                   = 0,
    PT_PACKETTYPE                = 1,
    PT_CLIENT_NAME               = 2,
    PT_CLIENT_CLOSING_CONNECTION = 3,
    PT_CLIENT_MESSAGE            = 4,
    PT_CLIENT_ESTABLISHED        = 5,
    PT_CLIENT_SENDFILE_INFO      = 6,
    PT_CLIENT_SENDFILE_CHUNK     = 7,
    PT_CLIENT_SENDFILE_TERMINATE = 8
} PacketType;

class Packet {
public:
    uint8_t m_type;

    Packet() : m_type (PT_UNKNOWN) { m_type = PT_PACKETTYPE; }
    virtual ~Packet() {}

    virtual size_t getMaxPacketSize() const { return 0; }
};

class PacketTypePacket : public Packet {
public:
    uint8_t type;

    PacketTypePacket() : type(PT_UNKNOWN) {}
    ~PacketTypePacket() {}
    size_t getMaxPacketSize() const { return sizeof(PacketTypePacket); }
};

class ClientNamePacket : public Packet {
public:
    char buffer[SERVER_MAXBUFSIZE];

    ClientNamePacket() { m_type = PT_CLIENT_NAME; }
    ~ClientNamePacket() {}

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE - 1; }
};

class ClientMessagePacket : public Packet {
public:
    char buffer[SERVER_MAXBUFSIZE];

    ClientMessagePacket() { m_type = PT_CLIENT_MESSAGE; }
    ~ClientMessagePacket() {}

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE - 1; }
};

class ClientSendFileInfoPacket : public Packet {
public:
    struct send_file_t info;

    ClientSendFileInfoPacket() { m_type = PT_CLIENT_SENDFILE_INFO; }
    ~ClientSendFileInfoPacket() {}

    size_t getMaxPacketSize() const { return sizeof(struct send_file_t); }
};

class ClientSendFileChunkPacket : public Packet {
public:
    char chunk[SERVER_MAXBUFSIZE];

    ClientSendFileChunkPacket() { m_type = PT_CLIENT_SENDFILE_CHUNK; }
    ~ClientSendFileChunkPacket() {}

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE; }
};

Packet* receive_client_packet(SOCKET sock, size_t min_packet_size = 0);
gerror_t send_client_packet   (SOCKET sock, uint8_t packet_type, const void* data, size_t sz);

GEND_DECL

#endif // __PACKET__H

