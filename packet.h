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
    PT_ENCRYPTED_CHUNK           = 11
} PacketType;

class Packet {
public:
    uint8_t m_type;

    Packet() : m_type (PT_UNKNOWN) { m_type = PT_PACKETTYPE; }
    virtual ~Packet() {}

    virtual size_t getMaxPacketSize() const { return 0; }
    static size_t GetPacketSize()           { return 0; }
};

template<PacketType Ptype>
class PacketPolicy : public Packet
{
public:
    PacketPolicy() {}
    virtual ~PacketPolicy() {}
};

// ----------  PT_PACKETTYPE ------------

template<>
class PacketPolicy<PT_PACKETTYPE> : public Packet {
public:
    uint8_t type;

    PacketPolicy() : type(PT_UNKNOWN) { m_type = PT_PACKETTYPE; }
    ~PacketPolicy() {}
    size_t getMaxPacketSize() const { return sizeof(PacketPolicy<PT_PACKETTYPE>); }
    static size_t GetPacketSize()   { return sizeof(PacketPolicy<PT_PACKETTYPE>); }
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

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE - 1; }
    static size_t GetPacketSize()   { return SERVER_MAXBUFSIZE - 1; }
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

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE - 1; }
    static size_t GetPacketSize()   { return SERVER_MAXBUFSIZE - 1; }
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

    size_t getMaxPacketSize() const { return sizeof(struct send_file_t); }
    static size_t GetPacketSize()   { return sizeof(struct send_file_t); }
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

    size_t getMaxPacketSize() const { return SERVER_MAXBUFSIZE; }
    static size_t GetPacketSize()   { return SERVER_MAXBUFSIZE; }
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

    size_t getMaxPacketSize() const { return sizeof(client_info_t); }
    static size_t GetPacketSize()   { return sizeof(client_info_t); }
};
typedef PacketPolicy<PT_CLIENT_INFO> ClientInfoPacket;

// --------------------------------------

template<>
class PacketPolicy<PT_ENCRYPTED_INFO> : public Packet {
public:
    encrypted_info_t info;

    PacketPolicy() { m_type = PT_ENCRYPTED_INFO; }
    ~PacketPolicy() {}

    size_t getMaxPacketSize() const { return sizeof(encrypted_info_t); }
    static size_t GetPacketSize()   { return sizeof(encrypted_info_t); }
};
typedef PacketPolicy<PT_ENCRYPTED_INFO> EncryptedInfoPacket;

template<>
class PacketPolicy<PT_ENCRYPTED_CHUNK> : public Packet {
public:
    unsigned char chunk[RSA_SIZE];

    PacketPolicy() { m_type = PT_ENCRYPTED_CHUNK; }
    ~PacketPolicy() {}

    size_t getMaxPacketSize() const { return RSA_SIZE; }
    static size_t GetPacketSize()   { return RSA_SIZE; }
};
typedef PacketPolicy<PT_ENCRYPTED_CHUNK> EncryptedChunkPacket;

Packet* packet_choose_policy(const int type);
Packet* packet_interpret(SOCKET sock, const uint8_t type, Packet* packet, unsigned char* data, size_t len);

Packet* receive_client_packet(SOCKET sock, size_t min_packet_size = 0);
gerror_t send_client_packet   (SOCKET sock, uint8_t packet_type, const void* data, size_t sz);

GEND_DECL

#endif // __PACKET__H

