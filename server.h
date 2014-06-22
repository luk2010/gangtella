/*
    This file is part of the GangTella project.
*/

#ifndef __SERVER__H
#define __SERVER__H

#include "prerequesites.h"
#include "client.h"
#include "encryption.h"
#include "packet.h"

GBEGIN_DECL

typedef std::map<uint32_t, client_t*> ClientsIdMap;
typedef gerror_t (*client_send_t) (client_t*, uint8_t, const void*, size_t);

typedef enum {
    SP_NORMAL  = 1,
    SP_CRYPTED = 2
} SendPolicy;

typedef struct _server_ {
    SOCKET                sock;

    std::string           name;         // Name displayed to other servers. This name is send to the client.
    std::vector<client_t> clients;      // List of activated clients.
    ClientsIdMap          client_by_id; // Every clients by ID. This list is updated for every clients connection or deconnection.

    pthread_mutex_t       mutex;
    pthread_t             thread;
    bool                  started;

    uint32_t              port;
    crypt_t*              crypt;        // RSA public/private key of this server.
    buffer_t*             pubkey;       // Public key ready to be send to new clients.

    client_send_t         client_send;  // Function to send packet. Can be crypted or not.
} server_t;


gerror_t server_create    (server_t* server, const std::string& disp_name);
gerror_t server_initialize(server_t* server, size_t port, int maxclients);
gerror_t server_launch    (server_t* server);
gerror_t server_destroy   (server_t* server);

gerror_t server_setsendpolicy(server_t* server, int policy);
Packet* server_receive_packet(server_t* server, client_t* client, size_t min_packet_size = 0);

client_t* server_find_client_by_name(server_t* server, const std::string& name);

gerror_t server_init_client_connection(server_t* server, client_t*& out, const char* adress, size_t port);
void server_end_client(server_t* server, const std::string& client_name);

GEND_DECL

#endif // __SERVER__H
