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

/** @brief A structure describing the client info needed by a server.
**/
struct client_info_t
{
    uint32_nt id;    // ID from mirror struct.
    uint32_nt idret; // ID from client struct.
    uint32_nt s_port;// Port for mirror struct.
    char      name[SERVER_MAXBUFSIZE];
    buffer_t  pubkey; // Public RSA Key.
};

template <> client_info_t serialize(const client_info_t&);
template <> client_info_t deserialize(const client_info_t&);

/** @brief Describe an encrypted info structure.
**/
struct encrypted_info_t {
    uint8_t   ptype;               // Packet type of decrypted data
    uint32_nt cryptedblock_number; // Number of crypted blocks.
    uint32_nt cryptedblock_lastsz; // Size of last crypted block (once decrypted).
};

template <> encrypted_info_t serialize(const encrypted_info_t&);
template <> encrypted_info_t deserialize(const encrypted_info_t&);

struct user_init_t {
	char name[SERVER_MAXBUFSIZE];
};

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
    PT_CLIENT_SENDFILE_TERMINATE = 8,
    PT_CLIENT_INFO               = 9,
    PT_ENCRYPTED_INFO            = 10,
    PT_ENCRYPTED_CHUNK           = 11,
    PT_HTTP_REQUEST              = 12,
    PT_USER_INIT                 = 13,
    PT_USER_INIT_RESPONSE        = 14,
    PT_USER_INIT_NOTACCEPTED     = 15,
    PT_USER_INIT_NOTLOGGED       = 16
} PacketType;

/** @brief A generic class representing a Packet.
 *  A Packet is a set of data of given size. This data
 *  is send by client to the host wich decrypt the data
 *  and fill this Packet structure depending on the PacketType.
 *
 *  @note
 *  A Packet of type PT_UNKNOWN is invalid.
**/
class Packet {
public:
    uint8_t m_type;///< Type of the packet.

    Packet() : m_type (PT_UNKNOWN) {}
    virtual ~Packet() {}

    /** @brief Return the size of this packet.
     *  @note This size doesn't take in amount the m_type
     *  component, as it is never send by client. You should only send
     *  the requested members in your data.
     *  Use packet_get_buffer() to get this buffer.
    **/
    virtual size_t getPacketSize() const { return 0; }

    /** @brief Returns the type of this packet.
    **/
    uint8_t getType() const { return m_type; }
};

/** @brief Helper class to make generic Packet extensions.
**/
template<PacketType Ptype>
class PacketPolicy : public Packet
{
public:
    PacketPolicy() {}
    virtual ~PacketPolicy() {}
};

// ----------  PT_PACKETTYPE ------------

/** @brief The first packet send to host is always this one.
 *  Use this Packet to tell the host you will send him a packet
 *  of given type. This type must be different from PT_UNKNOWN.
**/
template<>
class PacketPolicy<PT_PACKETTYPE> : public Packet {
public:
    uint8_t type;

    PacketPolicy() : type(PT_UNKNOWN) { m_type = PT_PACKETTYPE; }
    PacketPolicy(uint8_t _type) : type(_type) { m_type = PT_PACKETTYPE; }

    ~PacketPolicy() {}

    /** @note
     *  This is the only packet wich size corresponds to the whole object.
     *  We send the whole object through the Internet !
    **/
    size_t getPacketSize() const { return sizeof(PacketPolicy<PT_PACKETTYPE>); }
};
typedef PacketPolicy<PT_PACKETTYPE> PacketTypePacket;

// --------------------------------------

// ---------  PT_CLIENT_NAME ------------

template<>
class PacketPolicy<PT_CLIENT_NAME> : public Packet {
public:
    char buffer[SERVER_MAXBUFSIZE];

    PacketPolicy() { m_type = PT_CLIENT_NAME; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return SERVER_MAXBUFSIZE; }
};
typedef PacketPolicy<PT_CLIENT_NAME> ClientNamePacket;

// --------------------------------------

// --------- PT_CLIENT_MESSAGE ----------

template<>
class PacketPolicy<PT_CLIENT_MESSAGE> : public Packet {
public:
    char buffer[SERVER_MAXBUFSIZE];

    PacketPolicy() { m_type = PT_CLIENT_MESSAGE; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return SERVER_MAXBUFSIZE; }
};
typedef PacketPolicy<PT_CLIENT_MESSAGE> ClientMessagePacket;

// --------------------------------------

// ------ PT_CLIENT_SENDFILE_INFO -------

template<>
class PacketPolicy<PT_CLIENT_SENDFILE_INFO> : public Packet {
public:
    struct send_file_t info;

    PacketPolicy() { m_type = PT_CLIENT_SENDFILE_INFO; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return sizeof(struct send_file_t); }
};
typedef PacketPolicy<PT_CLIENT_SENDFILE_INFO> ClientSendFileInfoPacket;

// --------------------------------------

// ----- PT_CLIENT_SENDFILE_CHUNK -------

template<>
class PacketPolicy<PT_CLIENT_SENDFILE_CHUNK> : public Packet {
public:
    char chunk[SERVER_MAXBUFSIZE];

    PacketPolicy() { m_type = PT_CLIENT_SENDFILE_CHUNK; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return SERVER_MAXBUFSIZE; }
};
typedef PacketPolicy<PT_CLIENT_SENDFILE_CHUNK> ClientSendFileChunkPacket;

// --------------------------------------

// ---------- PT_CLIENT_INFO ------------

template<>
class PacketPolicy<PT_CLIENT_INFO> : public Packet {
public:
    client_info_t info;

    PacketPolicy() { m_type = PT_CLIENT_INFO; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return sizeof(client_info_t); }
};
typedef PacketPolicy<PT_CLIENT_INFO> ClientInfoPacket;

// --------------------------------------

template<>
class PacketPolicy<PT_ENCRYPTED_INFO> : public Packet {
public:
    encrypted_info_t info;

    PacketPolicy() { m_type = PT_ENCRYPTED_INFO; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return sizeof(encrypted_info_t); }
};
typedef PacketPolicy<PT_ENCRYPTED_INFO> EncryptedInfoPacket;

template<>
class PacketPolicy<PT_ENCRYPTED_CHUNK> : public Packet {
public:
    unsigned char chunk[RSA_SIZE];

    PacketPolicy() { m_type = PT_ENCRYPTED_CHUNK; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return RSA_SIZE; }
};
typedef PacketPolicy<PT_ENCRYPTED_CHUNK> EncryptedChunkPacket;

// ---------------------------------------

template<>
class PacketPolicy<PT_HTTP_REQUEST> : public Packet {
public:
    char request[SERVER_MAXBUFSIZE];

    PacketPolicy() { m_type = PT_HTTP_REQUEST; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return SERVER_MAXBUFSIZE; }
};
typedef PacketPolicy<PT_HTTP_REQUEST> HttpRequestPacket;

// ---------------------------------------

template<>
class PacketPolicy<PT_USER_INIT> : public Packet {
public:
    user_init_t data;

    PacketPolicy() { m_type = PT_USER_INIT; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return sizeof(user_init_t); }
};
typedef PacketPolicy<PT_USER_INIT> UserInitPacket;

template<>
class PacketPolicy<PT_USER_INIT_RESPONSE> : public Packet {
public:
    user_init_t data;

    PacketPolicy() { m_type = PT_USER_INIT_RESPONSE; }
    ~PacketPolicy() {}

    size_t getPacketSize() const { return sizeof(user_init_t); }
};
typedef PacketPolicy<PT_USER_INIT_RESPONSE> UserInitRPacket;



Packet* packet_choose_policy(const int type);
gerror_t packet_interpret(const uint8_t type, Packet* packet, data_t* data, size_t len);
gerror_t packet_get_buffer(Packet* p, unsigned char*& buf, size_t& sz);

Packet*  receive_client_packet(SOCKET sock);
gerror_t send_client_packet   (SOCKET sock, uint8_t packet_type, const void* data, size_t sz);

GEND_DECL

#endif // __PACKET__H

